package com.duwaini.shield.ui

import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.Settings
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Card
import androidx.compose.material3.FilterChip
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.core.graphics.drawable.toBitmap
import com.duwaini.shield.AppReport
import com.duwaini.shield.RiskLevel
import com.duwaini.shield.ShieldViewModel

@Composable
fun AppsScreen(vm: ShieldViewModel) {
    var filter by rememberSaveable { mutableIntStateOf(1) }
    val list = when (filter) {
        1 -> vm.apps.filter { it.level != RiskLevel.SAFE && it.packageName !in vm.trusted }
        else -> vm.apps
    }

    Column(Modifier.fillMaxSize()) {
        Row(Modifier.padding(horizontal = 16.dp, vertical = 8.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            FilterChip(filter == 1, { filter = 1 }, { Text("المشبوهة") })
            FilterChip(filter == 0, { filter = 0 }, { Text("الكل (${vm.apps.size})") })
        }
        if (vm.scanning) {
            LinearProgressIndicator(Modifier.fillMaxWidth().padding(horizontal = 16.dp))
            Text(vm.progress, Modifier.padding(horizontal = 16.dp), style = MaterialTheme.typography.bodySmall)
        }
        if (list.isEmpty() && !vm.scanning) {
            Text(
                if (vm.apps.isEmpty()) "اضغط «فحص سريع» من الرئيسية" else "مفيش تطبيقات مشبوهة 👍",
                Modifier.padding(24.dp),
            )
        }
        LazyColumn(
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            items(list, key = { it.packageName }) { app ->
                AppCard(app, app.packageName in vm.trusted, vm.scanning,
                    onCloud = { vm.cloudCheckApp(app.packageName) },
                    onTrust = { vm.toggleTrusted(app.packageName) })
            }
        }
    }
}

@Composable
private fun AppCard(
    app: AppReport,
    isTrusted: Boolean,
    busy: Boolean,
    onCloud: () -> Unit,
    onTrust: () -> Unit,
) {
    val ctx = LocalContext.current
    val icon = remember(app.packageName) {
        runCatching { ctx.packageManager.getApplicationIcon(app.packageName).toBitmap(96, 96).asImageBitmap() }.getOrNull()
    }
    val (badgeColor, badge) = when {
        isTrusted -> Color.Gray to "موثوق"
        app.level == RiskLevel.DANGER -> DangerRed to "خطر"
        app.level == RiskLevel.SUSPICIOUS -> WarnOrange to "مشبوه"
        else -> SafeGreen to "آمن"
    }

    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                if (icon != null) Image(icon, null, Modifier.size(40.dp))
                Spacer(Modifier.width(10.dp))
                Column(Modifier.weight(1f)) {
                    Text(app.label, fontWeight = FontWeight.Bold)
                    Text(app.packageName, style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                Text(badge, color = badgeColor, fontWeight = FontWeight.Bold)
            }
            app.reasons.forEach { Text("• $it", style = MaterialTheme.typography.bodySmall) }
            app.vtNote?.let {
                val bad = (app.vtMalicious ?: 0) > 0
                Text(it, color = if (bad) DangerRed else MaterialTheme.colorScheme.onSurface,
                    fontWeight = if (bad) FontWeight.Bold else FontWeight.Normal,
                    style = MaterialTheme.typography.bodySmall)
            }
            Row {
                TextButton(onClick = { uninstall(ctx, app.packageName) }) { Text("احذفه", color = DangerRed) }
                TextButton(onClick = { openDetails(ctx, app.packageName) }) { Text("صلاحياته") }
            }
            Row {
                TextButton(onClick = onCloud, enabled = !busy) { Text("افحصه أونلاين") }
                TextButton(onClick = onTrust) { Text(if (isTrusted) "إلغاء الثقة" else "أثق فيه") }
            }
        }
    }
}

private fun uninstall(ctx: Context, pkg: String) {
    try {
        ctx.startActivity(Intent(Intent.ACTION_DELETE, Uri.parse("package:$pkg")))
    } catch (e: ActivityNotFoundException) {
        openDetails(ctx, pkg)
    }
}

private fun openDetails(ctx: Context, pkg: String) {
    try {
        ctx.startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:$pkg")))
    } catch (e: Exception) { }
}
