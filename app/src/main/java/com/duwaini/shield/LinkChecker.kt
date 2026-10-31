package com.duwaini.shield

import java.net.URI
import java.util.Locale

data class LinkReport(
    val url: String,
    val host: String,
    val score: Int,
    val reasons: List<String>,
    val vt: VtResult? = null,
) {
    val level: RiskLevel
        get() {
            val mal = (vt as? VtResult.Found)?.malicious ?: 0
            return when {
                mal >= 2 || score >= 60 -> RiskLevel.DANGER
                mal >= 1 || score >= 25 -> RiskLevel.SUSPICIOUS
                else -> RiskLevel.SAFE
            }
        }
}

/** فحص الروابط من غير إنترنت: بيدور على علامات التصيّد المعروفة */
object LinkChecker {

    private val URL_REGEX = Regex("""(?i)\b((?:https?://|www\.)[^\s<>"'،]+)""")
    private val BARE_DOMAIN = Regex("""(?i)\b([a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}(?:/[^\s<>"'،]*)?)""")

    private val SHORTENERS = setOf(
        "bit.ly", "tinyurl.com", "t.ly", "cutt.ly", "is.gd", "rb.gy", "shorturl.at", "s.id",
        "ow.ly", "rebrand.ly", "tiny.cc", "shorte.st", "bitly.ws", "v.gd", "goo.su", "clck.ru",
    )
    private val RISKY_TLDS = setOf(
        "xyz", "top", "click", "cyou", "icu", "buzz", "rest", "sbs", "cfd", "quest", "lol",
        "bond", "vip", "monster", "live", "online", "site", "store", "fun", "support", "info",
    )
    private val BAIT_WORDS = listOf(
        "login", "signin", "verify", "verification", "update", "secure", "account", "otp",
        "wallet", "confirm", "unlock", "suspend", "refund", "prize", "gift", "reward",
    )

    /** يطلّع أول رابط من نص (رسالة واتساب مثلاً) */
    fun extractUrl(text: String): String? {
        val t = text.trim()
        URL_REGEX.find(t)?.let { m ->
            val u = m.value.trimEnd('.', ',', ')', ']', '!', '؟', '?')
            return if (u.startsWith("www.", ignoreCase = true)) "https://$u" else u
        }
        BARE_DOMAIN.find(t)?.let { return "https://" + it.value.trimEnd('.', ',', ')') }
        return null
    }

    /** الحروف العربي والمسافات في الرابط بتبوظ القراءة، فنحوّلها لصيغة %XX */
    private fun encodeUnsafe(url: String): String = buildString {
        for (ch in url) {
            if (ch.code in 33..126) append(ch)
            else ch.toString().toByteArray(Charsets.UTF_8).forEach { append("%%%02X".format(it)) }
        }
    }

    fun analyze(url: String): LinkReport? {
        val uri = try { URI(encodeUnsafe(url)) } catch (e: Exception) { return null }
        val host = (uri.host ?: return null).lowercase(Locale.ROOT).removeSuffix(".")
        var score = 0
        val reasons = mutableListOf<String>()
        fun add(points: Int, why: String) { score += points; reasons += why }

        BrandGuard.impersonatedByHost(host)?.let {
            add(60, "الموقع بيستخدم اسم «$it» بس مش موقعهم الرسمي — غالباً تصيّد")
        }
        if (uri.rawUserInfo != null || url.substringBefore(host).contains('@')) {
            add(35, "فيه علامة @ بتخبي الموقع الحقيقي")
        }
        if (Regex("""^\d{1,3}(\.\d{1,3}){3}$""").matches(host)) {
            add(30, "الرابط رقم IP مش اسم موقع — المواقع المحترمة مش بتعمل كده")
        }
        if (host.split('.').any { it.startsWith("xn--") }) {
            add(30, "اسم الموقع فيه حروف بتشبه حروف تانية (خدعة لتقليد مواقع)")
        }
        val tld = host.substringAfterLast('.')
        if (tld in RISKY_TLDS) add(20, "امتداد «.$tld» بيستخدمه النصابين كتير")
        if (host.removePrefix("www.") in SHORTENERS) {
            add(15, "رابط مختصر بيخبي الموقع الحقيقي — متفتحوش لو مش عارف مين باعته")
        }
        if (uri.scheme.equals("http", ignoreCase = true)) add(10, "الموقع مش مشفّر (http مش https)")
        if (host.count { it == '-' } >= 3) add(10, "اسم الموقع فيه شرط كتير")
        if (host.split('.').size >= 5) add(10, "الرابط فيه أجزاء كتير قبل اسم الموقع")
        val lower = url.lowercase(Locale.ROOT)
        BAIT_WORDS.firstOrNull { lower.contains(it) }?.let {
            add(10, "فيه كلمة «$it» — دي بتتكرر في روابط سرقة البيانات")
        }
        if (uri.path.orEmpty().lowercase(Locale.ROOT).endsWith(".apk")) {
            add(30, "الرابط بينزّل تطبيق APK — متثبتهوش")
        }

        return LinkReport(url, host, score.coerceAtMost(100), reasons)
    }
}
