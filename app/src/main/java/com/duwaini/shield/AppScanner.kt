package com.duwaini.shield

import android.Manifest
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import java.io.File
import java.io.InputStream
import java.security.MessageDigest

enum class RiskLevel { SAFE, SUSPICIOUS, DANGER }

data class AppReport(
    val packageName: String,
    val label: String,
    val apkPath: String,
    val installer: String?,
    val fromTrustedStore: Boolean,
    val score: Int,
    val reasons: List<String>,
    val vtMalicious: Int? = null,
    val vtTotal: Int? = null,
    val vtNote: String? = null,
    val sha256: String? = null,
) {
    val level: RiskLevel
        get() = when {
            (vtMalicious ?: 0) >= 3 || score >= 60 -> RiskLevel.DANGER
            (vtMalicious ?: 0) >= 1 || score >= 30 -> RiskLevel.SUSPICIOUS
            else -> RiskLevel.SAFE
        }
}

object AppScanner {

    private val TRUSTED_STORES = setOf(
        "com.android.vending",               // Google Play
        "com.sec.android.app.samsungapps",   // Galaxy Store
        "com.huawei.appmarket",              // AppGallery
        "com.amazon.venezia",
        "com.xiaomi.market",
        "com.xiaomi.mipicks",
        "com.heytap.market",
        "com.oppo.market",
        "com.bbk.appstore",
    )

    fun scan(ctx: Context, malwareDb: Set<String> = emptySet()): List<AppReport> {
        val pm = ctx.packageManager
        val cr = ctx.contentResolver
        val accessibility = splitServices(
            Settings.Secure.getString(cr, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES)
        )
        val notifListeners = splitServices(
            Settings.Secure.getString(cr, "enabled_notification_listeners")
        )
        val dpm = ctx.getSystemService(DevicePolicyManager::class.java)
        val admins = dpm?.activeAdmins?.map { it.packageName }?.toSet() ?: emptySet()

        return installedPackages(pm).mapNotNull { pi ->
            val ai = pi.applicationInfo ?: return@mapNotNull null
            if (ai.flags and ApplicationInfo.FLAG_SYSTEM != 0) return@mapNotNull null
            if (pi.packageName == ctx.packageName) return@mapNotNull null

            val pkg = pi.packageName
            val installer = installerOf(pm, pkg)
            val trusted = installer != null && installer in TRUSTED_STORES
            val requested = (pi.requestedPermissions ?: emptyArray()).toSet()
            val label = ai.loadLabel(pm).toString()
            val apkPath = ai.sourceDir ?: ""

            var score = 0
            val reasons = mutableListOf<String>()
            fun add(points: Int, why: String) { score += points; reasons += why }

            if (!trusted) add(15, "متثبت من برّه المتجر الرسمي")

            // بصمة التطبيقات اللي من برّه المتجر بس (تطبيقات المتجر بتاخد وقت ومتراجعة من جوجل)
            val hash = if (!trusted && apkPath.isNotEmpty()) {
                try { sha256(File(apkPath)) } catch (e: Exception) { null }
            } else null
            if (hash != null && hash in malwareDb) add(100, "⚠ موجود في قاعدة بيانات الفيروسات المعروفة")

            if (!trusted) {
                BrandGuard.impersonatedByApp(label, pkg)?.let {
                    add(60, "اسمه بيقلّد «$it» بس مش جاي من المتجر الرسمي — غالباً مزيّف")
                }
            }
            if (pkg in accessibility) add(30, "شغّال كـ«خدمة إمكانية وصول» — يقدر يشوف الشاشة ويضغط بدالك")
            if (pkg in admins) add(25, "عنده صلاحية «مسؤول الجهاز» — ده بيصعّب مسحه")
            if (pkg in notifListeners) add(15, "يقرأ كل الإشعارات اللي بتوصلك")
            if (!trusted && pm.getLaunchIntentForPackage(pkg) == null) {
                add(20, "مالوش أيقونة على الشاشة — مستخبي")
            }
            val (permScore, permReasons) = permissionRisk(requested)
            score += permScore
            reasons += permReasons

            // التطبيقات اللي من المتجر الرسمي متراجعة من جوجل، فنخفف وزنها
            if (trusted) score /= 2

            AppReport(
                packageName = pkg,
                label = label,
                apkPath = apkPath,
                sha256 = hash,
                installer = installer,
                fromTrustedStore = trusted,
                score = score.coerceAtMost(100),
                reasons = reasons,
            )
        }.sortedByDescending { it.score }
    }

    /** تقييم صلاحيات تطبيق (متثبت أو ملف APK) */
    fun permissionRisk(requested: Set<String>): Pair<Int, List<String>> {
        var score = 0
        val reasons = mutableListOf<String>()
        fun has(p: String) = p in requested
        fun add(points: Int, why: String) { score += points; reasons += why }

        val internet = has(Manifest.permission.INTERNET)
        if ((has(Manifest.permission.READ_SMS) || has(Manifest.permission.RECEIVE_SMS)) && internet) {
            add(25, "يقرأ الرسائل ومعاه إنترنت — ممكن يسرق أكواد التحقق")
        }
        if (has(Manifest.permission.SEND_SMS)) add(15, "يقدر يبعت رسائل SMS (ممكن تتخصم من رصيدك)")
        if (has(Manifest.permission.SYSTEM_ALERT_WINDOW)) add(10, "يقدر يظهر فوق التطبيقات التانية")
        if (has(Manifest.permission.REQUEST_INSTALL_PACKAGES)) add(10, "يقدر يثبت تطبيقات تانية")
        if (has(Manifest.permission.READ_CALL_LOG) || has("android.permission.PROCESS_OUTGOING_CALLS")) {
            add(10, "يقرأ سجل المكالمات")
        }
        if (has(Manifest.permission.READ_CONTACTS) && internet) add(5, "يقرأ جهات الاتصال")
        if (has(Manifest.permission.RECORD_AUDIO)) add(5, "يقدر يسجل صوت")
        if (has(Manifest.permission.BIND_ACCESSIBILITY_SERVICE)) add(10, "بيطلب يبقى خدمة إمكانية وصول")
        if (has(Manifest.permission.BIND_DEVICE_ADMIN)) add(10, "بيطلب صلاحية مسؤول الجهاز")
        return score to reasons
    }

    /** يحلل ملف APK مش متثبت: يرجع (اسم التطبيق، الأسباب) أو null لو مش APK (التقليد بيتحسب برّه) */
    fun analyzeArchive(ctx: Context, file: File): Pair<String, List<String>>? {
        val pm = ctx.packageManager
        val pi = archiveInfo(pm, file.absolutePath) ?: return null
        val ai = pi.applicationInfo
        val label = if (ai != null) {
            ai.sourceDir = file.absolutePath
            ai.publicSourceDir = file.absolutePath
            ai.loadLabel(pm).toString()
        } else pi.packageName
        val (_, permReasons) = permissionRisk((pi.requestedPermissions ?: emptyArray()).toSet())
        val reasons = mutableListOf<String>()
        BrandGuard.impersonatedByApp(label, pi.packageName)?.let {
            reasons += "اسمه بيقلّد «$it» — التطبيقات الرسمية بتتنزل من المتجر بس"
        }
        reasons += permReasons
        return label to reasons
    }

    fun isInstalled(ctx: Context, pkg: String): Boolean = try {
        ctx.packageManager.getApplicationInfo(pkg, 0); true
    } catch (e: PackageManager.NameNotFoundException) { false }

    fun sha256(file: File): String = file.inputStream().use { sha256(it) }

    fun sha256(input: InputStream): String {
        val md = MessageDigest.getInstance("SHA-256")
        val buf = ByteArray(64 * 1024)
        while (true) {
            val n = input.read(buf)
            if (n <= 0) break
            md.update(buf, 0, n)
        }
        return md.digest().joinToString("") { "%02x".format(it) }
    }

    private fun splitServices(raw: String?): Set<String> =
        raw.orEmpty().split(':').mapNotNull { s ->
            s.substringBefore('/', "").takeIf { it.isNotBlank() }
        }.toSet()

    @Suppress("DEPRECATION")
    private fun installedPackages(pm: PackageManager): List<PackageInfo> =
        if (Build.VERSION.SDK_INT >= 33) {
            pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong()))
        } else {
            pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
        }

    @Suppress("DEPRECATION")
    private fun archiveInfo(pm: PackageManager, path: String): PackageInfo? =
        if (Build.VERSION.SDK_INT >= 33) {
            pm.getPackageArchiveInfo(path, PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong()))
        } else {
            pm.getPackageArchiveInfo(path, PackageManager.GET_PERMISSIONS)
        }

    @Suppress("DEPRECATION")
    private fun installerOf(pm: PackageManager, pkg: String): String? = try {
        if (Build.VERSION.SDK_INT >= 30) pm.getInstallSourceInfo(pkg).installingPackageName
        else pm.getInstallerPackageName(pkg)
    } catch (e: Exception) { null }
}
