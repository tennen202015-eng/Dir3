package com.duwaini.shield.ui

import android.content.Intent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.duwaini.shield.ShieldViewModel

@Composable
fun DeviceScreen(vm: ShieldViewModel) {
    val ctx = LocalContext.current
    LazyColumn(contentPadding = PaddingValues(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        item {
            Text("فحص إعدادات الجهاز", fontSize = 20.sp, fontWeight = FontWeight.Bold)
            Spacer(Modifier.width(4.dp))
        }
        items(vm.checks) { c ->
            Card(Modifier.fillMaxWidth()) {
                Row(Modifier.padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
                    Text(if (c.ok) "✓" else "⚠", fontSize = 24.sp, color = if (c.ok) SafeGreen else WarnOrange)
                    Spacer(Modifier.width(12.dp))
                    Column(Modifier.weight(1f)) {
                        Text(c.title, fontWeight = FontWeight.Bold)
                        Text(c.detail, style = MaterialTheme.typography.bodySmall)
                    }
                    val action = c.settingsAction
                    if (!c.ok && action != null) {
                        TextButton(onClick = {
                            try { ctx.startActivity(Intent(action)) } catch (e: Exception) { }
                        }) { Text("ظبطه") }
                    }
                }
            }
        }
    }
}
