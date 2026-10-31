package com.duwaini.shield.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.duwaini.shield.LinkReport
import com.duwaini.shield.RiskLevel
import com.duwaini.shield.ShieldViewModel
import com.duwaini.shield.VtResult

@Composable
fun LinksScreen(vm: ShieldViewModel) {
    val clipboard = LocalClipboardManager.current

    Column(
        Modifier.verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("فحص الروابط", fontSize = 22.sp, fontWeight = FontWeight.Bold)
        Text(
            "جاتلك رسالة فيها رابط؟ الصقه هنا، أو اضغط «مشاركة» على الرسالة واختار «درع».",
            style = MaterialTheme.typography.bodyMedium,
        )
        OutlinedTextField(
            value = vm.linkInput,
            onValueChange = { vm.linkInput = it },
            label = { Text("الرابط أو الرسالة كلها") },
            modifier = Modifier.fillMaxWidth(),
            minLines = 2,
        )
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = { vm.checkLink() }, modifier = Modifier.height(48.dp)) { Text("افحص") }
            OutlinedButton(
                onClick = {
                    clipboard.getText()?.text?.let {
                        vm.linkInput = it
                        vm.checkLink()
                    }
                },
                modifier = Modifier.height(48.dp),
            ) { Text("الصق وافحص") }
        }
        if (vm.linkChecking) {
            LinearProgressIndicator(Modifier.fillMaxWidth())
            Text("بسأل VirusTotal...", style = MaterialTheme.typography.bodySmall)
        }
        vm.linkResult?.let { LinkResultCard(it, vm.vtKey.isNotBlank()) }

        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text("نصايح سريعة", fontWeight = FontWeight.Bold)
                listOf(
                    "البنوك وأبشر عمرهم ما هيطلبوا منك رمز التحقق في رسالة أو مكالمة.",
                    "رسايل «شحنتك متوقفة» و«حسابك هيتقفل» أشهر طرق النصب.",
                    "لو مش متأكد، افتح التطبيق الرسمي بنفسك بدل ما تضغط على الرابط.",
                ).forEach { Text("• $it", style = MaterialTheme.typography.bodySmall) }
            }
        }
    }
}

@Composable
private fun LinkResultCard(r: LinkReport, hasKey: Boolean) {
    val (color, title) = when (r.level) {
        RiskLevel.DANGER -> DangerRed to "⚠ خطر — متفتحوش"
        RiskLevel.SUSPICIOUS -> WarnOrange to "مشبوه — خلي بالك"
        RiskLevel.SAFE -> SafeGreen to "✓ مفيش علامات خطر"
    }
    Card(
        Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = color.copy(alpha = 0.12f)),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(title, color = color, fontSize = 20.sp, fontWeight = FontWeight.Bold)
            Text(r.host, fontWeight = FontWeight.Bold)
            r.reasons.forEach { Text("• $it", style = MaterialTheme.typography.bodySmall) }
            when (val vt = r.vt) {
                is VtResult.Found -> Text(
                    if (vt.malicious > 0) "VirusTotal: ${vt.malicious} من ${vt.total} برنامج حماية قالوا إنه ضار"
                    else "VirusTotal: نضيف عند ${vt.total} برنامج حماية",
                    color = if (vt.malicious > 0) DangerRed else Color.Unspecified,
                    fontWeight = FontWeight.Bold,
                )
                VtResult.NotFound -> Text(
                    "VirusTotal لسه ميعرفش الرابط ده — بعتناهوله يفحصه، جرّب تاني بعد دقيقة",
                    style = MaterialTheme.typography.bodySmall,
                )
                is VtResult.Failed -> Text(vt.message, style = MaterialTheme.typography.bodySmall, color = WarnOrange)
                null -> if (!hasKey) Text(
                    "ضيف مفتاح VirusTotal من الإعدادات عشان فحص أدق",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            if (r.level == RiskLevel.SAFE) {
                Text(
                    "ده مش ضمان 100% — لو الرسالة بتطلب بيانات أو فلوس، متدخلش حاجة.",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }
    }
}
