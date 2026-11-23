package kz.kzsigner.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.launch
import kz.kzsigner.core.Checked
import kz.kzsigner.core.Format
import kz.kzsigner.core.Reason
import kz.kzsigner.core.SignerCheck
import kz.kzsigner.core.Verdict
import kz.kzsigner.Files
import kz.kzsigner.KeysModel
import kz.kzsigner.Opened
import kz.kzsigner.R

/** The reason's title (screen 6c). */
fun reasonTitle(r: Reason?): Int = when (r) {
    Reason.CHANGED -> R.string.reason_changed
    Reason.REVOKED -> R.string.reason_revoked
    Reason.EXPIRED -> R.string.reason_expired
    Reason.EXPIRED_SINCE -> R.string.reason_expired_since
    Reason.NOT_RECOGNIZED -> R.string.reason_not_recognized
    Reason.DAMAGED -> R.string.reason_damaged
    Reason.NOT_CONFIRMED, null -> R.string.reason_not_confirmed
}

/** What to do about it: one next step. */
private fun reasonNext(r: Reason?): Int = when (r) {
    Reason.CHANGED -> R.string.reason_changed_next
    Reason.REVOKED -> R.string.reason_revoked_next
    Reason.EXPIRED -> R.string.reason_expired_next
    Reason.EXPIRED_SINCE -> R.string.reason_expired_since_next
    Reason.NOT_RECOGNIZED -> R.string.reason_not_recognized_next
    Reason.DAMAGED -> R.string.reason_damaged_next
    Reason.NOT_CONFIRMED, null -> R.string.unknown_next
}

/**
 * Screens 5, 5b, 5c, 5e, 6, 6b: what checking the file found. NCA is asked whether each key
 * was valid; until it answers, a spinner.
 */
@Composable
fun CheckScreen(
    model: KeysModel,
    onBack: () -> Unit,
    onDetails: () -> Unit,
    onRead: (Reading) -> Unit,
    onAnother: () -> Unit,
) {
    val file = model.checking ?: return
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val lang = LocalConfiguration.current.locales[0].language
    LaunchedEffect(file) { if (model.checked == null) model.check(lang) }
    val c = model.checked
    if (c == null) {
        Screen(onBack) {
            Column(
                Modifier.fillMaxWidth().padding(top = 120.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                CircularProgressIndicator()
                Body(stringResource(R.string.checking))
            }
        }
        return
    }
    val noApp = stringResource(R.string.no_app_opens)
    val tooBig = stringResource(R.string.too_big)
    val open: () -> Unit = open@{
        val d = c.document ?: return@open
        if (d.size >= 5 && String(d, 0, 5, Charsets.ISO_8859_1) == "%PDF-") {
            onRead(Reading(c.documentName, d))
        } else if (!Files.view(context, c.documentName, d)) {
            Toast.makeText(context, noApp, Toast.LENGTH_LONG).show()
        }
    }
    val signIt: () -> Unit = {
        // the app then goes to Sign with it (App.kt)
        scope.launch { model.signThis(file.name, file.bytes) }
    }
    val pickOriginal = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) {
            scope.launch {
                if (model.addOriginal(uri) == Opened.TOO_BIG) Toast.makeText(context, tooBig, Toast.LENGTH_LONG).show()
            }
        }
    }
    val canSign = !model.keys?.keys.isNullOrEmpty()

    when (c.verdict) {
        Verdict.NOT_SIGNED -> Screen(
            onBack,
            buttons = {
                if (canSign) MainButton(stringResource(R.string.sign_it_myself), signIt)
                SecondButton(stringResource(R.string.check_another), onAnother)
            },
        ) {
            Outcome(R.drawable.ic_file, stringResource(R.string.not_signed_title), stringResource(R.string.not_signed_body, file.name), Tone.GREY)
            Small(stringResource(R.string.not_signed_hint))
        }
        Verdict.NEEDS_DOCUMENT -> Screen(
            onBack,
            buttons = {
                MainButton(stringResource(R.string.choose_document), { pickOriginal.launch(arrayOf("*/*")) })
                SecondButton(stringResource(R.string.check_another), onAnother)
            },
        ) {
            Outcome(R.drawable.ic_file, stringResource(R.string.needs_document_title), stringResource(R.string.needs_document_body, c.documentName), Tone.GREY)
            if (c.signers.isNotEmpty()) SignerList(c, showState = false)
        }
        Verdict.VALID -> Screen(
            onBack,
            buttons = {
                if (c.document != null) MainButton(stringResource(R.string.open_document), open)
                if (canSign) SecondButton(stringResource(R.string.add_my_signature), signIt)
            },
        ) {
            val n = c.signers.size
            val confirmed = c.signers.all { it.ncaTime }
            Outcome(
                R.drawable.ic_shield_check,
                when (n) {
                    1 -> stringResource(R.string.valid_one)
                    2 -> stringResource(R.string.valid_two)
                    else -> stringResource(R.string.valid_all, n)
                },
                if (n == 1) stringResource(if (confirmed) R.string.valid_body else R.string.valid_body_today) else null,
                Tone.GOOD,
            )
            if (n == 1) OneSigner(c, c.signers[0]) else SignerList(c, showState = true)
            for (s in c.signers.filter { !it.ncaTime }) {
                s.expiresMs?.let {
                    WarnNotice(null, stringResource(R.string.no_nca_time_warning, firstName(s.name), longDate(it)))
                }
            }
            DetailsLink(onDetails)
        }
        Verdict.INVALID -> Screen(
            onBack,
            buttons = { SecondButton(stringResource(R.string.check_another), onAnother) },
        ) {
            val bad = c.signers.firstOrNull { !it.valid && it.reason != Reason.NOT_CONFIRMED } ?: c.signers.firstOrNull()
            Outcome(
                R.drawable.ic_shield_alert,
                stringResource(R.string.do_not_trust),
                stringResource(reasonTitle(bad?.reason)),
                Tone.BAD,
            )
            Grey(stringResource(reasonNext(bad?.reason)))
            if (c.signers.size > 1) SignerList(c, showState = true)
            DetailsLink(onDetails)
        }
        Verdict.UNKNOWN -> Screen(
            onBack,
            buttons = { MainButton(stringResource(R.string.check_again), { scope.launch { model.check(lang) } }) },
        ) {
            Outcome(R.drawable.ic_clock, stringResource(R.string.unknown_title), stringResource(R.string.unknown_body), Tone.WARN)
            Grey(stringResource(R.string.unknown_next))
            if (c.signers.size > 1) SignerList(c, showState = true)
            DetailsLink(onDetails)
        }
    }
}

private enum class Tone { GOOD, BAD, WARN, GREY }

/** The big coloured box at the top: icon, title, one line. */
@Composable
private fun Outcome(icon: Int, title: String, body: String?, tone: Tone) {
    val n = LocalNotices.current
    val (bg, fg, text) = when (tone) {
        Tone.GOOD -> Triple(n.goodBg, n.good, n.good)
        Tone.BAD -> Triple(n.badBg, MaterialTheme.colorScheme.error, MaterialTheme.colorScheme.error)
        Tone.WARN -> Triple(n.warnBg, n.warnTitle, n.warnText)
        Tone.GREY -> Triple(MaterialTheme.colorScheme.surfaceVariant, MaterialTheme.colorScheme.onSurface, MaterialTheme.colorScheme.onSurfaceVariant)
    }
    Column(
        Modifier.fillMaxWidth().background(bg, RoundedCornerShape(16.dp))
            .then(if (tone == Tone.GREY) Modifier.border(1.dp, MaterialTheme.colorScheme.outline, RoundedCornerShape(16.dp)) else Modifier)
            .padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Icon(painterResource(icon), null, tint = fg, modifier = Modifier.size(32.dp))
        Text(title, color = fg, fontSize = 24.sp, fontWeight = FontWeight.SemiBold, lineHeight = 29.sp, modifier = Modifier.semantics { heading() })
        body?.let { Text(it, color = text, style = MaterialTheme.typography.bodyLarge) }
    }
}

@Composable
private fun Grey(text: String) {
    Text(
        text,
        style = MaterialTheme.typography.bodyMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.fillMaxWidth().background(MaterialTheme.colorScheme.surfaceVariant, RoundedCornerShape(12.dp)).padding(14.dp),
    )
}

/** One row of the single-signer card: a small label over the value. */
@Composable
private fun Field(label: String, value: String, vararg more: String) {
    Column(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 12.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
        Small(label)
        Text(value, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
        for (m in more) Small(m)
    }
}

/** 5 and 5e: who signed, for whom, when, and the document. */
@Composable
private fun OneSigner(c: Checked, s: SignerCheck) {
    Column(Modifier.fillMaxWidth().border(1.dp, MaterialTheme.colorScheme.outline, RoundedCornerShape(14.dp))) {
        Field(stringResource(R.string.signed_by), displayName(s.name), *listOfNotNull(s.iin?.let { stringResource(R.string.iin, it) }).toTypedArray())
        s.company?.let {
            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
            Field(stringResource(R.string.on_behalf_of), it, *listOfNotNull(s.bin?.let { b -> stringResource(R.string.bin, b) }).toTypedArray())
        }
        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
        val t = s.signedMs
        if (s.ncaTime && t != null) {
            Field(stringResource(R.string.signed_on_label), dateTime(t))
        } else {
            Field(
                stringResource(R.string.signed_on_label),
                stringResource(R.string.not_confirmed_by_nca),
                *listOfNotNull(t?.let { stringResource(R.string.own_clock, dateTime(it)) }).toTypedArray(),
            )
        }
        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
        Field(stringResource(R.string.document), c.documentName)
    }
}

/** 5b, 6: every signer, each with a tick, or a cross and the reason. */
@Composable
private fun SignerList(c: Checked, showState: Boolean) {
    Column(Modifier.fillMaxWidth().border(1.dp, MaterialTheme.colorScheme.outline, RoundedCornerShape(14.dp))) {
        c.signers.forEachIndexed { i, s ->
            if (i > 0) HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
            Row(Modifier.padding(16.dp), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                if (showState) {
                    val (icon, tint) = when {
                        s.valid -> R.drawable.ic_check to LocalNotices.current.good
                        s.reason == Reason.NOT_CONFIRMED -> R.drawable.ic_clock to LocalNotices.current.warnTitle
                        else -> R.drawable.ic_x to MaterialTheme.colorScheme.error
                    }
                    Icon(painterResource(icon), null, tint = tint, modifier = Modifier.size(20.dp))
                }
                Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    Text(displayName(s.name), fontWeight = FontWeight.SemiBold)
                    val who = s.company?.let { co -> if (s.bin != null) stringResource(R.string.for_company_bin, co, s.bin!!) else stringResource(R.string.for_company, co) }
                        ?: s.iin?.let { stringResource(R.string.iin, it) }
                    who?.let { Small(it) }
                    s.signedMs?.let { Small(dateTime(it)) }
                    if (showState && !s.valid) Small(stringResource(reasonTitle(s.reason)), if (s.reason == Reason.NOT_CONFIRMED) LocalNotices.current.warnText else MaterialTheme.colorScheme.error)
                }
            }
        }
    }
}

@Composable
private fun DetailsLink(onClick: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().heightIn(min = 48.dp).clickable(role = Role.Button, onClick = onClick).padding(horizontal = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(stringResource(R.string.details), style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
        Icon(painterResource(R.drawable.ic_down), null, modifier = Modifier.size(20.dp))
    }
}

/** Screen 5d: the details, for checking by hand or by a specialist; Copy details. */
@Composable
fun CheckDetailsScreen(model: KeysModel, onBack: () -> Unit) {
    val c = model.checked ?: return
    val context = LocalContext.current
    val copied = stringResource(R.string.copied)
    val rows = mutableListOf<Pair<String, String>>()
    rows += stringResource(R.string.d_format) to stringResource(
        when (c.format) {
            Format.PDF -> R.string.f_pdf
            Format.XML -> R.string.f_xml
            Format.CMS -> R.string.f_cms
            Format.DETACHED_CMS -> R.string.f_detached
            Format.CARD -> R.string.f_card
            null -> R.string.f_none
        },
    )
    for (s in c.signers) {
        if (c.signers.size > 1) rows += stringResource(R.string.signed_by) to displayName(s.name)
        s.signedMs?.let {
            rows += stringResource(R.string.d_time) to dateTime(it) + "\n" +
                stringResource(if (s.ncaTime) R.string.d_time_nca else R.string.d_time_own)
        }
        s.revocation?.let { rows += stringResource(R.string.d_revocation) to it }
        val cert = listOfNotNull(s.algorithm, s.serial?.let { stringResource(R.string.d_serial, it) }).joinToString(" · ")
        val dates = if (s.validFromMs != null && s.expiresMs != null) {
            stringResource(R.string.d_valid, longDate(s.validFromMs!!), longDate(s.expiresMs!!))
        } else {
            ""
        }
        if (cert.isNotEmpty() || dates.isNotEmpty()) rows += stringResource(R.string.d_certificate) to listOf(cert, dates).filter { it.isNotEmpty() }.joinToString("\n")
        s.issuer?.let { rows += stringResource(R.string.d_issuer) to it }
        s.level?.let { rows += stringResource(R.string.d_level) to it }
        if (s.problems.isNotEmpty()) rows += stringResource(R.string.d_found) to s.problems.joinToString("\n")
    }
    c.fingerprint?.let { rows += stringResource(R.string.d_fingerprint) to "SHA-256 · " + it.take(8) + " … " + it.takeLast(8) }
    val all = rows.joinToString("\n\n") { it.first + "\n" + it.second } + (c.fingerprint?.let { "\n\nSHA-256: $it" } ?: "")
    Screen(
        onBack,
        buttons = {
            SecondButton(stringResource(R.string.copy_details)) {
                context.getSystemService(ClipboardManager::class.java)?.setPrimaryClip(ClipData.newPlainText("kzsigner", all))
                Toast.makeText(context, copied, Toast.LENGTH_SHORT).show()
            }
        },
    ) {
        Title(stringResource(R.string.details_title))
        Body(stringResource(R.string.details_body))
        Column(Modifier.fillMaxWidth().border(1.dp, MaterialTheme.colorScheme.outline, RoundedCornerShape(14.dp))) {
            rows.forEachIndexed { i, (k, v) ->
                if (i > 0) HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                Column(Modifier.padding(horizontal = 16.dp, vertical = 10.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    Small(k)
                    Text(v, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Medium, color = Color.Unspecified)
                }
            }
        }
    }
}
