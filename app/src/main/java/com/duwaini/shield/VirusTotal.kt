package com.duwaini.shield

import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

sealed class VtResult {
    data class Found(val malicious: Int, val suspicious: Int, val total: Int) : VtResult()
    data object NotFound : VtResult()
    data class Failed(val message: String, val stop: Boolean = false) : VtResult()
}

/** فحص البصمة (SHA-256) عند VirusTotal — أكتر من 70 برنامج حماية */
object VirusTotal {
    fun lookup(hash: String, apiKey: String): VtResult {
        if (apiKey.isBlank()) return VtResult.Failed("ضيف مفتاح VirusTotal من الإعدادات", stop = true)
        return try {
            val c = URL("https://www.virustotal.com/api/v3/files/$hash").openConnection() as HttpURLConnection
            c.setRequestProperty("x-apikey", apiKey)
            c.connectTimeout = 15000
            c.readTimeout = 15000
            try {
                when (c.responseCode) {
                    200 -> {
                        val body = c.inputStream.bufferedReader().use { it.readText() }
                        val stats = JSONObject(body)
                            .getJSONObject("data")
                            .getJSONObject("attributes")
                            .getJSONObject("last_analysis_stats")
                        var total = 0
                        for (k in stats.keys()) total += stats.optInt(k)
                        VtResult.Found(stats.optInt("malicious"), stats.optInt("suspicious"), total)
                    }
                    404 -> VtResult.NotFound
                    401, 403 -> VtResult.Failed("مفتاح VirusTotal غلط", stop = true)
                    429 -> VtResult.Failed("خلصت الحصة المجانية دلوقتي — جرب بعد شوية", stop = true)
                    else -> VtResult.Failed("خطأ من السيرفر (${c.responseCode})")
                }
            } finally {
                c.disconnect()
            }
        } catch (e: Exception) {
            VtResult.Failed("مفيش إنترنت أو حصل خطأ في الاتصال", stop = true)
        }
    }
}
