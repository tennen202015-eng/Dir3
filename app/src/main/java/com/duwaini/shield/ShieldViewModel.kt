package com.duwaini.shield

import android.app.Application
import android.net.Uri
import android.provider.OpenableColumns
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

data class FileScanResult(
    val name: String,
    val sha256: String,
    val vt: VtResult?,
    val apkLabel: String?,
    val apkReasons: List<String>?,
    val inMalwareDb: Boolean = false,
)

class ShieldViewModel(app: Application) : AndroidViewModel(app) {
    private val prefs = Prefs(app)
    private val ctx get() = getApplication<Application>()

    var apps by mutableStateOf<List<AppReport>>(emptyList()); private set
    var scanning by mutableStateOf(false); private set
    var progress by mutableStateOf(""); private set
    var checks by mutableStateOf<List<DeviceCheck>>(emptyList()); private set
    var lastScan by mutableStateOf(prefs.lastScan); private set
    var vtKey by mutableStateOf(prefs.vtKey); private set
    var autoScan by mutableStateOf(prefs.autoScan); private set
    var trusted by mutableStateOf(prefs.trusted); private set
    var fileResult by mutableStateOf<FileScanResult?>(null)
    var message by mutableStateOf<String?>(null)
    var tab by mutableIntStateOf(0)

    var dbCount by mutableIntStateOf(0); private set
    var dbUpdated by mutableStateOf(0L); private set

    var linkInput by mutableStateOf("")
    var linkResult by mutableStateOf<LinkReport?>(null); private set
    var linkChecking by mutableStateOf(false); private set

    init {
        refreshChecks()
        viewModelScope.launch {
            withContext(Dispatchers.IO) {
                MalwareDb.updateIfNeeded(ctx)
                MalwareDb.hashes(ctx)
            }
            refreshDbInfo()
            quickScan()
        }
    }

    private fun refreshDbInfo() {
        dbCount = MalwareDb.hashes(ctx).size
        dbUpdated = MalwareDb.lastUpdate(ctx)
    }

    fun updateDbNow() {
        viewModelScope.launch {
            val ok = withContext(Dispatchers.IO) {
                val r = MalwareDb.updateIfNeeded(ctx, force = true)
                MalwareDb.hashes(ctx)
                r
            }
            refreshDbInfo()
            message = if (ok) "قاعدة الفيروسات اتحدثت: $dbCount بصمة" else "مقدرتش أحدّث القاعدة — اتأكد من الإنترنت"
        }
    }

    /** رابط جاي من زرار المشاركة أو متلصّق */
    fun shareReceived(text: String) {
        linkInput = text
        tab = 1
        checkLink()
    }

    fun checkLink() {
        val url = LinkChecker.extractUrl(linkInput)
        if (url == null) { message = "مش لاقي رابط في النص ده"; return }
        val base = LinkChecker.analyze(url)
        if (base == null) { message = "الرابط ده مش مفهوم"; return }
        linkResult = base
        if (vtKey.isBlank()) return
        viewModelScope.launch {
            linkChecking = true
            val vt = withContext(Dispatchers.IO) { VirusTotal.lookupUrl(url, vtKey) }
            if (linkResult?.url == url) linkResult = base.copy(vt = vt)
            linkChecking = false
        }
    }

    fun refreshChecks() {
        checks = DeviceChecks.run(ctx)
    }

    /** بعد الرجوع للتطبيق: نشيل اللي اتمسح */
    fun onResume() {
        refreshChecks()
        if (apps.isNotEmpty()) apps = apps.filter { AppScanner.isInstalled(ctx, it.packageName) }
    }

    fun quickScan() {
        if (scanning) return
        viewModelScope.launch {
            scanning = true
            progress = "بفحص التطبيقات..."
            try {
                apps = withContext(Dispatchers.IO) { AppScanner.scan(ctx, MalwareDb.hashes(ctx)) }
                prefs.knownPackages = apps.map { it.packageName }.toSet()
                prefs.lastScan = System.currentTimeMillis()
                lastScan = prefs.lastScan
            } catch (e: Exception) {
                message = "حصل خطأ في الفحص: ${e.message}"
            }
            scanning = false
        }
    }

    /** فحص سحابي: بيبعت بصمة التطبيقات اللي من برّه المتجر أو المشبوهة لـ VirusTotal */
    fun cloudScan() {
        if (scanning) return
        if (vtKey.isBlank()) { message = "عشان الفحص السحابي، ضيف مفتاح VirusTotal المجاني من صفحة الإعدادات."; return }
        viewModelScope.launch {
            scanning = true
            if (apps.isEmpty()) apps = withContext(Dispatchers.IO) { AppScanner.scan(ctx, MalwareDb.hashes(ctx)) }
            val targets = apps.filter { !it.fromTrustedStore || it.level != RiskLevel.SAFE }
            if (targets.isEmpty()) {
                message = "كل تطبيقاتك من المتجر الرسمي ومفيش حاجة مشبوهة 👍"
            }
            for ((i, a) in targets.withIndex()) {
                progress = "فحص سحابي ${i + 1} من ${targets.size}: ${a.label}"
                val r = checkOne(a)
                if (r is VtResult.Failed && r.stop) { message = r.message; break }
                // الحساب المجاني: 4 طلبات في الدقيقة
                if (i < targets.size - 1) delay(16_000)
            }
            scanning = false
        }
    }

    fun cloudCheckApp(pkg: String) {
        if (scanning) return
        if (vtKey.isBlank()) { message = "ضيف مفتاح VirusTotal من الإعدادات الأول."; return }
        val a = apps.firstOrNull { it.packageName == pkg } ?: return
        viewModelScope.launch {
            scanning = true
            progress = "فحص سحابي: ${a.label}"
            val r = checkOne(a)
            if (r is VtResult.Failed) message = r.message
            scanning = false
        }
    }

    private suspend fun checkOne(a: AppReport): VtResult {
        val r = withContext(Dispatchers.IO) {
            try {
                VirusTotal.lookup(a.sha256 ?: AppScanner.sha256(File(a.apkPath)), vtKey)
            } catch (e: Exception) {
                VtResult.Failed("مقدرتش أقرأ ملف التطبيق")
            }
        }
        val updated = when (r) {
            is VtResult.Found -> a.copy(
                vtMalicious = r.malicious, vtTotal = r.total,
                vtNote = if (r.malicious == 0) "نضيف عند ${r.total} برنامج حماية"
                else "${r.malicious} من ${r.total} برنامج حماية قالوا إنه فيروس",
            )
            VtResult.NotFound -> a.copy(vtNote = "VirusTotal ميعرفوش — مش معناها إنه فيروس، بس خلي بالك")
            is VtResult.Failed -> a
        }
        apps = apps.map { if (it.packageName == a.packageName) updated else it }
        return r
    }

    fun scanFile(uri: Uri) {
        if (scanning) return
        viewModelScope.launch {
            scanning = true
            progress = "بفحص الملف..."
            try {
                fileResult = withContext(Dispatchers.IO) {
                    val name = displayName(uri)
                    val tmp = File(ctx.cacheDir, "scan_target.tmp")
                    ctx.contentResolver.openInputStream(uri)?.use { ins ->
                        tmp.outputStream().use { ins.copyTo(it) }
                    } ?: throw IllegalStateException("مقدرتش أفتح الملف")
                    val hash = AppScanner.sha256(tmp)
                    val apk = AppScanner.analyzeArchive(ctx, tmp)
                    val known = hash in MalwareDb.hashes(ctx)
                    val vt = if (vtKey.isNotBlank()) VirusTotal.lookup(hash, vtKey) else null
                    tmp.delete()
                    FileScanResult(name, hash, vt, apk?.first, apk?.second, known)
                }
            } catch (e: Exception) {
                message = e.message ?: "حصل خطأ"
            }
            scanning = false
        }
    }

    private fun displayName(uri: Uri): String {
        ctx.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
            if (c.moveToFirst()) return c.getString(0) ?: "ملف"
        }
        return uri.lastPathSegment ?: "ملف"
    }

    fun toggleTrusted(pkg: String) {
        trusted = if (pkg in trusted) trusted - pkg else trusted + pkg
        prefs.trusted = trusted
    }

    fun saveVtKey(key: String) {
        prefs.vtKey = key
        vtKey = prefs.vtKey
        message = if (vtKey.isBlank()) "اتمسح المفتاح" else "اتحفظ المفتاح ✓"
    }

    fun setAuto(enabled: Boolean) {
        prefs.autoScan = enabled
        autoScan = enabled
        ScanWorker.schedule(ctx, enabled)
    }
}
