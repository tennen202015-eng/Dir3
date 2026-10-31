package com.duwaini.shield.ui

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.duwaini.shield.FileScanResult
import com.duwaini.shield.RiskLevel
import com.duwaini.shield.ShieldViewModel
import com.duwaini.shield.VtResult
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun HomeScreen(vm: ShieldViewModel, openApps: () -> Unit, openDevice: () -> Unit) {
    val active = vm.apps.filter { it.packageName !in vm.trusted }
    val danger = active.count { it.level == RiskLevel.DANGER }
    val suspicious = active.count { it.level == RiskLevel.SUSPICIOUS }
    val deviceIssues = vm.checks.count { !it.ok }

    val (color, title, symbol) = when {
        vm.lastScan == 0L && vm.apps.isEmpty() -> Triple(Color.Gray, "اعمل أول فحص", "?")
        danger > 0 -> Triple(DangerRed, "في خطر على جوالك", "!")
        suspicious > 0 || deviceIssues > 0 -> Triple(WarnOrange, "محتاج انتباهك", "!")
        else -> Triple(SafeGreen, "جوالك آمن", "✓")
    }

    val pickFile = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) vm.scanFile(uri)
    }

    Column(
        Modifier.verticalScroll(rememberScrollState()).padding(20.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Spacer(Modifier.height(8.dp))
        Box(contentAlignment = Alignment.Center) {
            ShieldShape(color, Modifier.size(150.dp, 170.dp))
            Text(symbol, color = Color.White, fontSize = 64.sp, fontWeight = FontWeight.Bold)
        }
        Text(title, fontSize = 26.sp, fontWeight = FontWeight.Bold, color = color)

        if (vm.apps.isNotEmpty()) {
            Text(
                "فحصت ${vm.apps.size} تطبيق · $danger خطر · $suspicious مشبوه",
                style = MaterialTheme.typography.bodyMedium,
            )
            if (danger + suspicious > 0) TextButton(onClick = openApps) { Text("شوف التطبيقات") }
        }
        if (deviceIssues > 0) {
            TextButton(onClick = openDevice) { Text("في $deviceIssues إعداد في الجهاز محتاج يتظبط") }
        }
        if (vm.lastScan > 0) {
            Text(
                "آخر فحص: " + SimpleDateFormat("yyyy/MM/dd  HH:mm", Locale.getDefault()).format(Date(vm.lastScan)),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        if (vm.scanning) {
            LinearProgressIndicator(Modifier.fillMaxWidth())
            Text(vm.progress, style = MaterialTheme.typography.bodySmall, textAlign = TextAlign.Center)
        }

        Button(onClick = { vm.quickScan() }, enabled = !vm.scanning, modifier = Modifier.fillMaxWidth().height(52.dp)) {
            Text("فحص سريع", fontSize = 17.sp)
        }
        OutlinedButton(onClick = { vm.cloudScan() }, enabled = !vm.scanning, modifier = Modifier.fillMaxWidth().height(52.dp)) {
            Text("فحص سحابي عميق (VirusTotal)")
        }
        OutlinedButton(
            onClick = { pickFile.launch(arrayOf("*/*")) },
            enabled = !vm.scanning,
            modifier = Modifier.fillMaxWidth().height(52.dp),
        ) {
            Text("افحص ملف أو APK قبل ما تفتحه")
        }

        vm.fileResult?.let { FileResultCard(it) { vm.fileResult = null } }
    }
}

@Composable
private fun FileResultCard(r: FileScanResult, onClose: () -> Unit) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(r.name, fontWeight = FontWeight.Bold)
            r.apkLabel?.let { Text("تطبيق: $it") }
            if (r.inMalwareDb) {
                Text("⚠ الملف ده موجود في قاعدة بيانات الفيروسات — امسحه فوراً",
                    color = DangerRed, fontWeight = FontWeight.Bold)
            }
            when (val vt = r.vt) {
                is VtResult.Found -> {
                    val bad = vt.malicious > 0
                    Text(
                        if (bad) "⚠ ${vt.malicious} من ${vt.total} برنامج حماية قالوا إنه فيروس — متفتحوش"
                        else "✓ نضيف عند ${vt.total} برنامج حماية",
                        color = if (bad) DangerRed else SafeGreen, fontWeight = FontWeight.Bold,
                    )
                }
                VtResult.NotFound -> Text("VirusTotal ميعرفش الملف ده — لو جايلك من حد مش معروف متفتحوش", color = WarnOrange)
                is VtResult.Failed -> Text(vt.message, color = WarnOrange)
                null -> Text("ضيف مفتاح VirusTotal من الإعدادات عشان أفحص الملف أونلاين", color = WarnOrange)
            }
            r.apkReasons?.takeIf { it.isNotEmpty() }?.let { reasons ->
                Text("الصلاحيات اللي بيطلبها:", fontWeight = FontWeight.Bold)
                reasons.forEach { Text("• $it", style = MaterialTheme.typography.bodySmall) }
            }
            Text("البصمة: ${r.sha256.take(16)}…", style = MaterialTheme.typography.bodySmall)
            TextButton(onClick = onClose) { Text("قفل") }
        }
    }
}

@Composable
fun ShieldShape(color: Color, modifier: Modifier = Modifier) {
    Canvas(modifier) {
        val w = size.width
        val h = size.height
        val p = Path().apply {
            moveTo(w / 2f, 0f)
            lineTo(w, h * 0.17f)
            lineTo(w, h * 0.48f)
            cubicTo(w, h * 0.76f, w * 0.72f, h * 0.93f, w / 2f, h)
            cubicTo(w * 0.28f, h * 0.93f, 0f, h * 0.76f, 0f, h * 0.48f)
            lineTo(0f, h * 0.17f)
            close()
        }
        drawPath(p, color)
    }
}
