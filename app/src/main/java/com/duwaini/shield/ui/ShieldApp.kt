package com.duwaini.shield.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.List
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Phone
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.unit.LayoutDirection
import com.duwaini.shield.ShieldViewModel

val SafeGreen = Color(0xFF0F7B5A)
val WarnOrange = Color(0xFFE08A00)
val DangerRed = Color(0xFFC62828)

@Composable
fun ShieldApp(vm: ShieldViewModel) {
    val colors = if (isSystemInDarkTheme()) {
        darkColorScheme(primary = Color(0xFF4FD1A1), secondary = Color(0xFF4FD1A1))
    } else {
        lightColorScheme(primary = SafeGreen, secondary = SafeGreen)
    }
    CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Rtl) {
        MaterialTheme(colorScheme = colors) {
            var tab by rememberSaveable { mutableIntStateOf(0) }
            Scaffold(
                bottomBar = {
                    NavigationBar {
                        NavigationBarItem(tab == 0, { tab = 0 }, { Icon(Icons.Filled.Home, null) }, label = { Text("الرئيسية") })
                        NavigationBarItem(tab == 1, { tab = 1 }, { Icon(Icons.AutoMirrored.Filled.List, null) }, label = { Text("التطبيقات") })
                        NavigationBarItem(tab == 2, { tab = 2 }, { Icon(Icons.Filled.Phone, null) }, label = { Text("الجهاز") })
                        NavigationBarItem(tab == 3, { tab = 3 }, { Icon(Icons.Filled.Settings, null) }, label = { Text("الإعدادات") })
                    }
                },
            ) { pad ->
                Box(Modifier.padding(pad).fillMaxSize()) {
                    when (tab) {
                        0 -> HomeScreen(vm, openApps = { tab = 1 }, openDevice = { tab = 2 })
                        1 -> AppsScreen(vm)
                        2 -> DeviceScreen(vm)
                        else -> SettingsScreen(vm)
                    }
                }
            }
            vm.message?.let { msg ->
                AlertDialog(
                    onDismissRequest = { vm.message = null },
                    confirmButton = { TextButton(onClick = { vm.message = null }) { Text("تمام") } },
                    text = { Text(msg) },
                )
            }
        }
    }
}
