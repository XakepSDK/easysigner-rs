package kz.kzsigner.ui

import android.graphics.Bitmap
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.FilterQuality
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import kotlinx.coroutines.launch
import kz.kzsigner.AppModel
import kz.kzsigner.Desking
import kz.kzsigner.InPersonFlow
import kz.kzsigner.R
import kz.kzsigner.core.ChipPrompt
import kz.kzsigner.core.KeyInfo
import kz.kzsigner.core.MeetException
import kz.kzsigner.core.Person
import kz.kzsigner.core.SignException
import kz.kzsigner.core.Signed
import kz.kzsigner.core.Turn
import kz.kzsigner.core.Unlock
import kz.kzsigner.core.Visit

/** Signing in person: the lawyer's side (the document here) or a signer's (scan a QR code). */
@Composable
fun InPersonScreen(onBack: () -> Unit, onHost: () -> Unit, onJoin: () -> Unit) {
    Screen(onBack) {
        Title(stringResource(R.string.in_person_title))
        Choice(R.drawable.ic_file, stringResource(R.string.in_person_host), stringResource(R.string.in_person_host_body), primary = true, onHost)
        Choice(R.drawable.ic_pen, stringResource(R.string.in_person_join), stringResource(R.string.in_person_join_body), primary = false, onJoin)
        InfoNotice(stringResource(R.string.in_person_wifi))
    }
}

@Composable
private fun Choice(icon: Int, title: String, body: String, primary: Boolean, onClick: () -> Unit) {
    Surface(
        onClick = onClick,
        shape = RoundedCornerShape(20.dp),
        color = if (primary) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.surfaceVariant,
        contentColor = if (primary) MaterialTheme.colorScheme.onPrimary else MaterialTheme.colorScheme.onSurface,
        border = if (primary) null else BorderStroke(1.dp, MaterialTheme.colorScheme.outline),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(Modifier.padding(22.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Icon(painterResource(icon), null, modifier = Modifier.size(28.dp))
            Spacer(Modifier.size(2.dp))
            Text(title, fontSize = 22.sp, fontWeight = FontWeight.SemiBold)
            Text(body, style = MaterialTheme.typography.bodyLarge)
        }
    }
}

/** The key that signs here: the first that can, as on Sign. */
fun signingKey(model: AppModel): KeyInfo? {
    val keys = model.keys?.keys.orEmpty()
    return keys.firstOrNull { it.cantSign == null } ?: keys.firstOrNull()
}

private fun KeyInfo.needsPassword() = unlock == Unlock.PASSWORD || unlock == Unlock.FINGERPRINT_AND_PASSWORD

/** "You sign as", and the key's password field when it is kept under one. */
@Composable
private fun SignAs(key: KeyInfo, password: String, wrong: Boolean, onPassword: (String) -> Unit) {
    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
        Small(stringResource(R.string.you_sign_as))
        Text(displayName(key.name), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
        key.company?.let { c -> Small(if (key.bin != null) c + " · " + stringResource(R.string.bin, key.bin!!) else c) }
    }
    if (key.needsPassword()) {
        OutlinedTextField(
            value = password,
            onValueChange = onPassword,
            label = { Text(stringResource(R.string.key_password)) },
            singleLine = true,
            isError = wrong,
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
            shape = RoundedCornerShape(12.dp),
            modifier = Modifier.fillMaxWidth()
        )
        if (wrong) Small(stringResource(R.string.wrong_password), MaterialTheme.colorScheme.error)
    }
}

/** What a failed signing says; null when nothing needs saying (cancelled). */
@Composable
private fun signProblem(e: SignException?, online: () -> Boolean): String? = when (e) {
    null, is SignException.Cancelled, is SignException.WrongPassword -> null
    is SignException.NoAnswer -> stringResource(if (online()) R.string.nca_down_title else R.string.no_internet_title)
    is SignException.KeyCantSign -> stringResource(R.string.cant_sign_unknown_title)
    is SignException.KeyReset -> stringResource(R.string.key_reset)
    is SignException.Failed -> stringResource(R.string.sign_failed, e.detail)
    else -> e.toString()
}

/** A QR code, drawn crisp at any size. */
@Composable
fun QrCode(text: String, modifier: Modifier = Modifier) {
    val bitmap = remember(text) { qrBitmap(text) }
    Box(
        modifier.background(Color.White, RoundedCornerShape(16.dp)).border(1.dp, MaterialTheme.colorScheme.outline, RoundedCornerShape(16.dp)).padding(14.dp)
    ) {
        Image(bitmap, null, Modifier.fillMaxWidth().aspectRatio(1f), contentScale = ContentScale.Fit, filterQuality = FilterQuality.None)
    }
}

private fun qrBitmap(text: String): ImageBitmap {
    val hints = mapOf(EncodeHintType.MARGIN to 0, EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M)
    val m = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, 0, 0, hints)
    val px = IntArray(m.width * m.height) { i -> if (m.get(i % m.width, i / m.width)) 0xFF000000.toInt() else -1 }
    return Bitmap.createBitmap(px, m.width, m.height, Bitmap.Config.ARGB_8888).asImageBitmap()
}

/** A person who signed: a green tick and their name. */
@Composable
private fun SignerRow(name: String) {
    Row(horizontalArrangement = Arrangement.spacedBy(12.dp), verticalAlignment = Alignment.CenterVertically) {
        Box(Modifier.size(28.dp).background(LocalNotices.current.goodBg, CircleShape), contentAlignment = Alignment.Center) {
            Icon(painterResource(R.drawable.ic_check), null, tint = LocalNotices.current.good, modifier = Modifier.size(16.dp))
        }
        Text(displayName(name), style = MaterialTheme.typography.bodyLarge, maxLines = 1, overflow = TextOverflow.Ellipsis)
    }
}

@Composable
private fun SignedSoFar(signers: List<Person>) {
    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Label(stringResource(R.string.meet_signed_so_far))
        if (signers.isEmpty()) Small(stringResource(R.string.meet_nobody_yet))
        for (s in signers) SignerRow(s.name)
    }
}

/** The file's row: its type and name, and Read it. */
@Composable
private fun FileRow(name: String, onRead: (() -> Unit)?) {
    Row(
        Modifier.fillMaxWidth().border(1.dp, MaterialTheme.colorScheme.outline, RoundedCornerShape(14.dp)).padding(14.dp),
        horizontalArrangement = Arrangement.spacedBy(14.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(Modifier.size(44.dp).background(LocalNotices.current.badBg, RoundedCornerShape(10.dp)), contentAlignment = Alignment.Center) {
            Text("PDF", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = MaterialTheme.colorScheme.error)
        }
        Text(name, fontWeight = FontWeight.SemiBold, maxLines = 2, overflow = TextOverflow.MiddleEllipsis, modifier = Modifier.weight(1f))
        if (onRead != null) {
            TextButton(onClick = onRead) { Text(stringResource(R.string.read_it), fontWeight = FontWeight.SemiBold) }
        }
    }
}

/** A spinner, with [text] beside it when there is one. */
@Composable
private fun Waiting(text: String? = null) {
    if (text == null) {
        Box(Modifier.fillMaxWidth().padding(top = 24.dp), contentAlignment = Alignment.Center) {
            CircularProgressIndicator(Modifier.size(44.dp), strokeWidth = 3.5.dp)
        }
        return
    }
    Row(horizontalArrangement = Arrangement.spacedBy(14.dp), verticalAlignment = Alignment.CenterVertically) {
        CircularProgressIndicator(Modifier.size(24.dp), strokeWidth = 2.5.dp)
        Body(text)
    }
}

@Composable
private fun Big(icon: Int, good: Boolean, title: String, body: String?) {
    val n = LocalNotices.current
    Column(Modifier.fillMaxWidth().padding(top = 24.dp), horizontalAlignment = Alignment.CenterHorizontally) {
        Box(Modifier.size(80.dp).background(if (good) n.goodBg else n.warnBg, CircleShape), contentAlignment = Alignment.Center) {
            Icon(painterResource(icon), null, tint = if (good) n.good else n.warnTitle, modifier = Modifier.size(40.dp))
        }
        Spacer(Modifier.size(20.dp))
        Text(title, fontSize = 28.sp, fontWeight = FontWeight.SemiBold, textAlign = TextAlign.Center, modifier = Modifier.semantics { heading() })
        if (body != null) {
            Spacer(Modifier.size(10.dp))
            Text(body, style = MaterialTheme.typography.bodyLarge, color = MaterialTheme.colorScheme.onSurfaceVariant, textAlign = TextAlign.Center)
        }
    }
}

// ---- the lawyer's phone ----

/**
 * The lawyer's side: the document, then one QR code per signer, each signer's arrival and
 * their signature to accept or reject, and at the end the finished document, which each
 * signer collects by scanning again.
 */
@Composable
fun MeetScreen(key: KeyInfo, online: () -> Boolean, flow: InPersonFlow, onBack: () -> Unit, onRead: (Reading) -> Unit) {
    val m = flow.meeting
    val done = flow.finished
    when {
        m == null -> MeetStart(key, online, flow, onBack, onRead)
        done != null -> MeetDone(flow, done, onBack)
        else -> when (val d = flow.desk) {
            is Desking.Showing -> MeetQr(flow, onBack)
            is Desking.Here -> Screen(onBack) {
                Title(stringResource(R.string.meet_here_title, displayName(d.who.name)))
                d.who.iin?.let { Body(stringResource(R.string.iin, it)) }
                Body(stringResource(R.string.meet_here_body))
                Waiting()
            }
            is Desking.Deciding -> MeetDecide(flow, d, onBack)
        }
    }
}

@Composable
private fun MeetStart(key: KeyInfo, online: () -> Boolean, flow: InPersonFlow, onBack: () -> Unit, onRead: (Reading) -> Unit) {
    val paper = flow.paper ?: return
    val scope = rememberCoroutineScope()
    var signFirst by remember { mutableStateOf(true) }
    var password by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var wrong by remember { mutableStateOf(false) }
    var failure by remember { mutableStateOf<SignException?>(null) }
    val lang = LocalConfiguration.current.locales[0].language
    val prompt = ChipPrompt(stringResource(R.string.prompt_sign_title, paper.name), stringResource(R.string.prompt_sign_subtitle), "")
    val problem = signProblem(failure, online)
    Screen(
        onBack,
        buttons = {
            MainButton(
                stringResource(if (signFirst) R.string.meet_start else R.string.meet_start_no_sign),
                onClick = {
                    busy = true
                    failure = null
                    wrong = false
                    scope.launch {
                        try {
                            flow.start(key.id, if (key.needsPassword()) password else null, prompt, lang, signFirst)
                        } catch (e: SignException) {
                            failure = e
                            wrong = e is SignException.WrongPassword
                        } finally {
                            busy = false
                        }
                    }
                },
                enabled = !key.needsPassword() || password.isNotEmpty(),
                busy = busy
            )
        }
    ) {
        Title(stringResource(R.string.meet_start_title))
        FileRow(paper.name) { onRead(Reading(paper.name, paper.bytes)) }
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Label(stringResource(R.string.meet_sign_first))
                Small(stringResource(R.string.meet_sign_first_body))
            }
            Switch(checked = signFirst, onCheckedChange = { signFirst = it })
        }
        SignAs(key, password, wrong) {
            password = it
            wrong = false
        }
        problem?.let { Small(it, MaterialTheme.colorScheme.error) }
        InfoNotice(stringResource(R.string.in_person_wifi))
    }
}

@Composable
private fun TurnNotice(t: Turn?) {
    val n = LocalNotices.current
    when (t) {
        is Turn.Signed -> Notice(stringResource(R.string.meet_turn_signed, displayName(t.name)), null, n.goodBg, n.good, n.good, R.drawable.ic_check)
        is Turn.Collected -> Notice(stringResource(R.string.meet_turn_collected, displayName(t.name)), null, n.goodBg, n.good, n.good, R.drawable.ic_check)
        is Turn.Rejected -> WarnNotice(stringResource(R.string.meet_turn_rejected, displayName(t.name)), null)
        is Turn.Left -> WarnNotice(stringResource(R.string.meet_turn_left), null)
        is Turn.Refused -> WarnNotice(stringResource(R.string.meet_turn_refused, t.why), null)
        else -> {}
    }
}

@Composable
private fun MeetQr(flow: InPersonFlow, onBack: () -> Unit) {
    val scope = rememberCoroutineScope()
    var busy by remember { mutableStateOf(false) }
    var failure by remember { mutableStateOf<SignException?>(null) }
    val problem = signProblem(failure) { true }
    Screen(
        onBack,
        buttons = {
            MainButton(
                stringResource(R.string.meet_finish),
                onClick = {
                    busy = true
                    scope.launch {
                        try {
                            flow.finish()
                        } catch (e: SignException) {
                            failure = e
                        } finally {
                            busy = false
                        }
                    }
                },
                enabled = flow.signers.isNotEmpty(),
                busy = busy
            )
        }
    ) {
        TurnNotice(flow.last)
        Title(stringResource(R.string.meet_qr_title))
        Body(stringResource(R.string.meet_qr_body, flow.signers.size + 1))
        flow.qr?.let { QrCode(it, Modifier.fillMaxWidth().padding(horizontal = 24.dp)) }
        SignedSoFar(flow.signers)
        problem?.let { Small(it, MaterialTheme.colorScheme.error) }
    }
}

@Composable
private fun MeetDecide(flow: InPersonFlow, d: Desking.Deciding, onBack: () -> Unit) {
    val who = d.who
    Screen(
        onBack,
        buttons = {
            MainButton(stringResource(R.string.accept), onClick = { flow.decide(true) })
            SecondButton(stringResource(R.string.reject)) { flow.decide(false) }
        }
    ) {
        Title(stringResource(R.string.meet_decide_title))
        Card {
            Text(displayName(who.name), style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold)
            who.iin?.let { Body(stringResource(R.string.iin, it), MaterialTheme.colorScheme.onSurface) }
            who.company?.let { c -> Small(if (who.bin != null) c + " · " + stringResource(R.string.bin, who.bin!!) else c) }
            who.ncaTimeMs?.let { Small(stringResource(R.string.meet_signed_at, dateTime(it))) }
        }
        InfoNotice(stringResource(R.string.meet_decide_check), R.drawable.ic_shield_check)
    }
}

@Composable
private fun MeetDone(flow: InPersonFlow, done: Signed, onBack: () -> Unit) {
    val context = androidx.compose.ui.platform.LocalContext.current
    Screen(
        onBack,
        buttons = {
            Button(
                onClick = { kz.kzsigner.Files.send(context, done.name, done.bytes) },
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier.fillMaxWidth().heightIn(min = 56.dp)
            ) {
                Icon(painterResource(R.drawable.ic_share), null, Modifier.size(22.dp))
                Box(Modifier.width(10.dp))
                Text(stringResource(R.string.send), fontSize = 17.sp, fontWeight = FontWeight.SemiBold)
            }
            TextButton(onClick = onBack, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) {
                Text(stringResource(R.string.done))
            }
        }
    ) {
        TurnNotice(flow.last)
        Title(stringResource(R.string.meet_done_title))
        Body(stringResource(R.string.meet_done_body))
        flow.qr?.let { QrCode(it, Modifier.fillMaxWidth().padding(horizontal = 24.dp)) }
        FileRow(done.name, null)
        SignedSoFar(flow.signers)
    }
}

// ---- a signer's phone ----

/**
 * A signer's side: scan the QR code, read the document, sign, and wait for the lawyer's Accept;
 * later, scan again for the signed copy. [onScan] opens the camera and gives the code read.
 */
@Composable
fun VisitScreen(
    key: KeyInfo,
    online: () -> Boolean,
    flow: InPersonFlow,
    onBack: () -> Unit,
    onRead: (Reading) -> Unit,
    onScan: ((String) -> Unit) -> Unit
) {
    val scope = rememberCoroutineScope()
    var connecting by remember { mutableStateOf(false) }
    var trouble by remember { mutableStateOf<MeetException?>(null) }
    val join: (String) -> Unit = { code ->
        connecting = true
        trouble = null
        scope.launch {
            try {
                flow.join(key.id, code, online())
            } catch (e: MeetException) {
                trouble = e
            } finally {
                connecting = false
            }
        }
    }
    val scan = { onScan(join) }
    val visit = flow.visit
    val outcome = flow.outcome
    when {
        visit == null -> VisitScan(connecting, trouble, onBack, scan)
        outcome != null -> {
            val host = displayName(flow.host.orEmpty())
            Screen(
                onBack = null,
                buttons = {
                    if (outcome.accepted) MainButton(stringResource(R.string.scan_again), scan)
                    TextButton(onClick = onBack, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text(stringResource(R.string.done)) }
                }
            ) {
                if (outcome.accepted) {
                    Big(R.drawable.ic_check, true, stringResource(R.string.signed_title), stringResource(R.string.visit_accepted_body, host))
                } else {
                    Big(R.drawable.ic_x, false, stringResource(R.string.visit_rejected_title), stringResource(R.string.visit_rejected_body, host))
                }
            }
        }
        visit is Visit.Sign -> VisitSign(online, flow, key, visit, onBack, onRead)
        visit is Visit.Signed -> {
            val doc = visit.document
            if (doc != null) {
                val name = flow.title?.let { it.substringBeforeLast('.') + "-signed.pdf" } ?: "signed.pdf"
                SignedFile(Signed(doc, name, null, true), stringResource(R.string.visit_copy_title), onBack)
            } else {
                Screen(onBack = null, buttons = {
                    MainButton(stringResource(R.string.scan_again), scan)
                    TextButton(onClick = onBack, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text(stringResource(R.string.done)) }
                }) {
                    Big(R.drawable.ic_clock, true, stringResource(R.string.visit_wait_copy_title), stringResource(R.string.visit_wait_copy_body))
                }
            }
        }
        visit is Visit.Refused -> Screen(onBack) {
            Big(R.drawable.ic_x, false, stringResource(R.string.visit_refused_title), visit.why)
        }
    }
}

@Composable
private fun VisitScan(connecting: Boolean, trouble: MeetException?, onBack: () -> Unit, scan: () -> Unit) {
    Screen(onBack, buttons = { MainButton(stringResource(R.string.visit_scan), scan, busy = connecting) }) {
        Title(stringResource(R.string.visit_scan_title))
        Body(stringResource(R.string.visit_scan_body))
        Box(
            Modifier.fillMaxWidth().padding(vertical = 12.dp),
            contentAlignment = Alignment.Center
        ) {
            Box(
                Modifier.size(180.dp).border(3.dp, MaterialTheme.colorScheme.primary, RoundedCornerShape(24.dp)),
                contentAlignment = Alignment.Center
            ) {
                Icon(painterResource(R.drawable.ic_pen), null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(56.dp))
            }
        }
        if (connecting) Waiting(stringResource(R.string.visit_connecting))
        when (trouble) {
            null -> InfoNotice(stringResource(R.string.in_person_wifi))
            is MeetException.NotAnInvitation -> WarnNotice(stringResource(R.string.visit_not_invitation), null)
            is MeetException.Unreachable -> WarnNotice(stringResource(R.string.visit_unreachable), null)
            is MeetException.Lost -> WarnNotice(stringResource(R.string.visit_lost, trouble.why), null)
            is MeetException.Failed -> WarnNotice(stringResource(R.string.sign_failed, trouble.detail), null)
        }
    }
}

@Composable
private fun VisitSign(online: () -> Boolean, flow: InPersonFlow, key: KeyInfo, ask: Visit.Sign, onBack: () -> Unit, onRead: (Reading) -> Unit) {
    val scope = rememberCoroutineScope()
    var password by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var wrong by remember { mutableStateOf(false) }
    var failure by remember { mutableStateOf<SignException?>(null) }
    val lang = LocalConfiguration.current.locales[0].language
    val prompt = ChipPrompt(stringResource(R.string.prompt_sign_title, ask.title), stringResource(R.string.prompt_sign_subtitle), "")
    val problem = signProblem(failure, online)
    val reading = flow.reading
    val host = displayName(ask.lawyer)
    val decline = {
        flow.leave()
        onBack()
    }
    if (busy) {
        Screen(onBack = null) {
            Title(stringResource(R.string.visit_waiting_title, host))
            Body(stringResource(R.string.visit_waiting_body))
            Waiting()
        }
        return
    }
    Screen(
        decline,
        buttons = {
            if (reading?.matches != false) {
                SignButton(stringResource(R.string.sign), fingerprint = !key.needsPassword(), enabled = !key.needsPassword() || password.isNotEmpty()) {
                    busy = true
                    failure = null
                    wrong = false
                    scope.launch {
                        try {
                            flow.sign(if (key.needsPassword()) password else null, prompt, lang)
                        } catch (e: SignException) {
                            failure = e
                            wrong = e is SignException.WrongPassword
                        } finally {
                            busy = false
                        }
                    }
                }
            }
            SecondButton(stringResource(R.string.decline), decline)
        }
    ) {
        Small(stringResource(R.string.visit_asks, host))
        Title(stringResource(R.string.sign_title))
        FileRow(ask.title, reading?.let { r -> { onRead(Reading(ask.title, r.pdf)) } })
        Small(stringResource(R.string.visit_number, ask.number.toInt()))
        if (reading?.matches == false) WarnNotice(stringResource(R.string.visit_mismatch), null)
        val earlier = reading?.signers.orEmpty()
        if (earlier.isNotEmpty()) {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Label(stringResource(R.string.meet_signed_so_far))
                for (s in earlier) SignerRow(s.name)
            }
        }
        SignAs(key, password, wrong) {
            password = it
            wrong = false
        }
        problem?.let { Small(it, MaterialTheme.colorScheme.error) }
    }
}

/** The main button with the fingerprint, as on Sign. */
@Composable
private fun SignButton(text: String, fingerprint: Boolean, enabled: Boolean, onClick: () -> Unit) {
    Button(
        onClick = onClick,
        enabled = enabled,
        shape = RoundedCornerShape(12.dp),
        modifier = Modifier.fillMaxWidth().heightIn(min = 56.dp)
    ) {
        if (fingerprint) {
            Icon(painterResource(R.drawable.ic_fingerprint), null, Modifier.size(22.dp))
            Box(Modifier.width(10.dp))
        }
        Text(text, fontSize = 17.sp, fontWeight = FontWeight.SemiBold)
    }
}
