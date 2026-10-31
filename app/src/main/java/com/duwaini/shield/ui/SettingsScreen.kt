package com.duwaini.shield.ui

import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.duwaini.shield.ShieldViewModel
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun SettingsScreen(vm: ShieldViewModel) {
    val ctx = LocalContext.current
    var key by remember { mutableStateOf(vm.vtKey) }

    Column(
        Modifier.verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("مفتاح VirusTotal (مجاني)", fontWeight = FontWeight.Bold)
                Text(
                    "ده اللي بيخلي التطبيق يفحص كل تطبيق وملف عند أكتر من 70 برنامج حماية. " +
                        "اعمل حساب مجاني في VirusTotal، وبعدين من صورتك فوق اختار API key وانسخه هنا.",
                    style = MaterialTheme.typography.bodySmall,
                )
                OutlinedTextField(
                    value = key, onValueChange = { key = it },
                    label = { Text("API key") }, singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Row {
                    Button(onClick = { vm.saveVtKey(key) }) { Text("حفظ") }
                    TextButton(onClick = {
                        try {
                            ctx.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://www.virustotal.com/gui/join-us")))
                        } catch (e: Exception) { }
                    }) { Text("اعمل حساب") }
                }
            }
        }

        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text("قاعدة الفيروسات", fontWeight = FontWeight.Bold)
                Text(
                    if (vm.dbCount == 0) "لسه مفيش بصمات — هتتحدث تلقائياً أول ما تكون جاهزة"
                    else "${vm.dbCount} بصمة فيروس أندرويد معروفة",
                    style = MaterialTheme.typography.bodySmall,
                )
                if (vm.dbUpdated > 0) {
                    Text(
                        "آخر تحديث: " + SimpleDateFormat("yyyy/MM/dd HH:mm", Locale.getDefault()).format(Date(vm.dbUpdated)),
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
                TextButton(onClick = { vm.updateDbNow() }) { Text("حدّثها دلوقتي") }
            }
        }

        Card(Modifier.fillMaxWidth()) {
            Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text("فحص تلقائي", fontWeight = FontWeight.Bold)
                    Text("كل 6 ساعات في الخلفية، وينبهك لو لقى تطبيق جديد مشبوه",
                        style = MaterialTheme.typography.bodySmall)
                }
                Switch(checked = vm.autoScan, onCheckedChange = { vm.setAuto(it) })
            }
        }

        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text("التطبيق بيعمل إيه بالظبط؟", fontWeight = FontWeight.Bold)
                listOf(
                    "يراجع كل تطبيق متثبت: جاي منين، وبيطلب صلاحيات إيه، وهل مستخبي أو ماسك الجهاز.",
                    "يكشف التطبيقات والروابط اللي بتقلّد البنوك وأبشر وواتساب وغيرهم.",
                    "يقارن التطبيقات اللي من برّه المتجر بقاعدة فيروسات بتتحدث كل يوم.",
                    "يبعت «بصمة» التطبيق بس (مش التطبيق نفسه ولا بياناتك) لـ VirusTotal.",
                    "يفحص إعدادات الجوال: القفل، التحديثات، خيارات المطور، الروت.",
                    "أندرويد مش بيسمح لأي تطبيق يدخل جوه بيانات التطبيقات التانية، فده بيكمّل Google Play Protect ومش بديل عنه.",
                ).forEach { Text("• $it", style = MaterialTheme.typography.bodySmall) }
            }
        }
    }
}
