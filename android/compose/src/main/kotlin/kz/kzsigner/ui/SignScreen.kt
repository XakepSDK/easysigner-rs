package kz.kzsigner.ui

import android.text.format.Formatter
import android.widget.Toast
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.launch
import kz.kzsigner.core.CantSign
import kz.kzsigner.core.Checked
import kz.kzsigner.core.Reason
import kz.kzsigner.core.SignerCheck
import kz.kzsigner.core.ChipPrompt
import kz.kzsigner.core.DocKind
import kz.kzsigner.core.KeyInfo
import kz.kzsigner.core.Output
import kz.kzsigner.core.SignException
import kz.kzsigner.core.SignedBy
import kz.kzsigner.core.Unlock
import kz.kzsigner.core.cmsContent
import kz.kzsigner.DocFile
import kz.kzsigner.Files
import kz.kzsigner.KeysModel
import kz.kzsigner.R

/** Why the key can't sign, with its dates: screen 3f. */
class Refusal(val reason: CantSign, val validFromMs: Long, val expiresMs: Long)

/** A document to read in the app's PDF reader. */
class Reading(val name: String, val bytes: ByteArray)

/**
 * Screens 3, 3b, 3c, 3d, 3e and 3g: the document, who signs it, what signing makes, and one
 * Sign button (one fingerprint or screen-lock prompt; the key's password on a phone without
 * a screen lock). NCA checks the key before the prompt: no internet shows 3c, a key that
 * can't sign goes to [onCantSign].
 */
@Composable
fun SignScreen(
    model: KeysModel,
    onBack: () -> Unit,
    onRead: (Reading) -> Unit,
    onSigned: () -> Unit,
    onCantSign: (Refusal) -> Unit,
) {
    val doc = model.document ?: return
    val keys = model.keys?.keys.orEmpty()
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var keyId by rememberSaveable { mutableStateOf(keys.firstOrNull { it.cantSign == null }?.id ?: keys.firstOrNull()?.id) }
    val key = keys.firstOrNull { it.id == keyId } ?: keys.firstOrNull() ?: return
    var password by remember { mutableStateOf("") }
    var shown by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var wrong by remember { mutableStateOf(false) }
    var problem by remember { mutableStateOf<String?>(null) }
    /** NCA didn't answer: true without internet, false when NCA is down. */
    var noAnswer by remember { mutableStateOf<Boolean?>(null) }

    val info = doc.info
    // a file the app can't show itself: the person may open it in another app, not must
    val shownElsewhere = info.kind == DocKind.OTHER || info.kind == DocKind.XML
    val needsPassword = key.unlock == Unlock.PASSWORD || key.unlock == Unlock.FINGERPRINT_AND_PASSWORD
    val joins = info.signers.isNotEmpty()
    val lang = LocalConfiguration.current.locales[0].language
    val prompt = ChipPrompt(stringResource(R.string.prompt_sign_title, doc.name), stringResource(R.string.prompt_sign_subtitle), "")
    val noApp = stringResource(R.string.no_app_opens)
    val resetText = stringResource(R.string.key_reset)

    val sign: () -> Unit = sign@{
        if (busy || (needsPassword && password.isEmpty())) return@sign
        busy = true
        problem = null
        wrong = false
        scope.launch {
            try {
                model.sign(key.id, if (needsPassword) password else null, prompt, lang)
                password = ""
                noAnswer = null
                onSigned()
            } catch (e: SignException) {
                when (e) {
                    is SignException.NoAnswer -> noAnswer = model.online().not()
                    is SignException.KeyCantSign -> onCantSign(Refusal(e.reason, e.validFromMs, e.expiresMs))
                    is SignException.WrongPassword -> wrong = true
                    is SignException.Wait -> problem = context.resources.getQuantityString(
                        R.plurals.wait_seconds, e.seconds.toInt(), e.seconds.toInt(),
                    )
                    is SignException.Cancelled -> {}
                    is SignException.KeyReset -> problem = resetText
                    is SignException.NoSuchKey -> problem = e.toString()
                    is SignException.Cannot -> {}
                    is SignException.Failed -> problem = context.getString(R.string.sign_failed, e.detail)
                }
            } finally {
                busy = false
            }
        }
    }

    val off = noAnswer
    if (off != null) {
        // 3c: nothing was signed or asked
        Screen(onBack, buttons = { MainButton(stringResource(R.string.try_again), sign, busy = busy) }) {
            Title(stringResource(if (joins) R.string.add_sign_title else R.string.sign_title))
            DocRow(doc)
            val n = LocalNotices.current
            Notice(
                stringResource(if (off) R.string.no_internet_title else R.string.nca_down_title),
                stringResource(if (off) R.string.no_internet_body else R.string.nca_down_body),
                n.warnBg, n.warnTitle, n.warnText, R.drawable.ic_wifi_off,
            )
        }
        return
    }

    val read_: () -> Unit = {
        val inner = if (info.kind == DocKind.CMS) cmsContent(doc.bytes) else null
        when {
            info.kind == DocKind.PDF -> onRead(Reading(doc.name, doc.bytes))
            inner != null && info.innerKind == DocKind.PDF -> onRead(Reading(info.innerName ?: doc.name, inner))
            inner != null -> if (!Files.view(context, info.innerName ?: doc.name, inner)) {
                Toast.makeText(context, noApp, Toast.LENGTH_LONG).show()
            }
            else -> if (!Files.view(context, doc.name, doc.bytes)) {
                Toast.makeText(context, noApp, Toast.LENGTH_LONG).show()
            }
        }
    }

    val canSign = info.output != Output.CANNOT
    Screen(
        onBack,
        buttons = {
            if (canSign) {
                SignButton(
                    stringResource(if (info.kind == DocKind.CMS) R.string.add_my_signature else R.string.sign),
                    fingerprint = !needsPassword && info.kind != DocKind.CMS,
                    enabled = !needsPassword || password.isNotEmpty(),
                    busy = busy,
                    onClick = sign,
                )
                if (shownElsewhere) {
                    Small(stringResource(R.string.open_to_check), modifier = Modifier.fillMaxWidth(), center = true)
                }
                if (keys.size > 1) KeyPicker(keys, key) { keyId = it.id; password = ""; wrong = false }
            }
        },
    ) {
        Title(stringResource(if (joins) R.string.add_sign_title else R.string.sign_title))
        if (info.kind == DocKind.CMS) CmsCard(doc, read_) else DocCard(doc, read_)
        // who signed already, and once NCA has answered, whether their signatures hold
        val checked by produceState<Checked?>(null, doc) {
            // another document: forget the last one's check first
            value = null
            if (info.signers.isNotEmpty()) value = model.checkQuietly(doc.name, doc.bytes, lang)
        }
        val rows = checked?.signers?.takeIf { it.isNotEmpty() }
        if (rows != null) {
            for (s in rows) AlreadySigned(SignedBy(s.name, s.company, s.signedMs), s)
        } else {
            for (s in info.signers) AlreadySigned(s, null)
        }
        if (!canSign) {
            Body(stringResource(if (info.kind == DocKind.XML) R.string.cannot_xml else R.string.cannot_detached))
            return@Screen
        }
        Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Small(stringResource(R.string.you_sign_as))
            Text(displayName(key.name), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            key.company?.let { c -> Small(if (key.bin != null) c + " · " + stringResource(R.string.bin, key.bin!!) else c) }
        }
        if (needsPassword) {
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                OutlinedTextField(
                    value = password,
                    onValueChange = { password = it; wrong = false },
                    label = { Text(stringResource(R.string.key_password)) },
                    singleLine = true,
                    isError = wrong,
                    visualTransformation = if (shown) VisualTransformation.None else PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, imeAction = ImeAction.Done),
                    keyboardActions = KeyboardActions(onDone = { sign() }),
                    trailingIcon = {
                        IconButton(onClick = { shown = !shown }) {
                            Icon(
                                painterResource(if (shown) R.drawable.ic_eye_off else R.drawable.ic_eye),
                                stringResource(if (shown) R.string.hide_password else R.string.show_password),
                            )
                        }
                    },
                    shape = RoundedCornerShape(12.dp),
                    modifier = Modifier.fillMaxWidth(),
                )
                if (wrong) {
                    Small(stringResource(R.string.wrong_password), MaterialTheme.colorScheme.error)
                    if (password.any { it in 'Ѐ'..'ӿ' }) {
                        WarnNotice(stringResource(R.string.keyboard_title), stringResource(R.string.keyboard_detail))
                    }
                }
            }
        }
        problem?.let { Small(it, MaterialTheme.colorScheme.error) }
        val first = info.signers.firstOrNull()?.let { displayName(it.name) } ?: ""
        Grey(
            stringResource(
                when (info.output) {
                    Output.INSIDE_PDF -> when {
                        joins && info.whoSignedPage -> R.string.out_pdf_join_page
                        joins -> R.string.out_pdf_join
                        else -> R.string.out_pdf
                    }
                    Output.INSIDE_XML -> R.string.out_xml
                    Output.JOIN_CMS -> R.string.out_cms_join
                    else -> R.string.out_cms
                },
                first,
            ),
        )
        if (needsPassword && key.unlock == Unlock.PASSWORD) {
            Grey(stringResource(if (model.screenLock) R.string.sign_password_nochip else R.string.sign_password_nolock))
        }
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

@Composable
private fun Small(text: String, modifier: Modifier, center: Boolean) {
    Text(
        text,
        style = MaterialTheme.typography.bodyMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        textAlign = if (center) TextAlign.Center else null,
        modifier = modifier,
    )
}

/** The main button, with the fingerprint when that's what it asks for. */
@Composable
private fun SignButton(text: String, fingerprint: Boolean, enabled: Boolean, busy: Boolean, onClick: () -> Unit) {
    Button(
        onClick = onClick,
        enabled = enabled && !busy,
        shape = RoundedCornerShape(12.dp),
        colors = ButtonDefaults.buttonColors(),
        modifier = Modifier.fillMaxWidth().heightIn(min = 56.dp),
    ) {
        if (busy) {
            CircularProgressIndicator(Modifier.size(22.dp), strokeWidth = 2.5.dp, color = MaterialTheme.colorScheme.onPrimary)
        } else {
            if (fingerprint) {
                Icon(painterResource(R.drawable.ic_fingerprint), null, Modifier.size(22.dp))
                Box(Modifier.width(10.dp))
            }
            Text(text, fontSize = 17.sp, fontWeight = FontWeight.SemiBold)
        }
    }
}

/** The file type's short label: PDF, DOCX, XML. */
private fun ext(name: String): String = name.substringAfterLast('.', "").uppercase().take(4).ifEmpty { "FILE" }

/** A small coloured square with the file type, as the design's file cards. */
@Composable
private fun TypeBadge(name: String, size: Int = 52) {
    val pdf = ext(name) == "PDF"
    Box(
        Modifier.size(size.dp).background(
            if (pdf) LocalNotices.current.badBg else LocalNotices.current.infoBg,
            RoundedCornerShape(10.dp),
        ),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            ext(name),
            fontSize = 12.sp,
            fontWeight = FontWeight.Bold,
            color = if (pdf) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary,
        )
    }
}

/** 3, 3b, 3g: the document's first page (PDF) or its type, its name, and Read it. */
@Composable
private fun DocCard(doc: DocFile, onRead: () -> Unit) {
    val context = LocalContext.current
    val pdf = rememberPdfPreview(if (doc.info.kind == DocKind.PDF) doc.bytes else null)
    Column(Modifier.fillMaxWidth().border(1.dp, MaterialTheme.colorScheme.outline, RoundedCornerShape(14.dp))) {
        Box(
            Modifier.fillMaxWidth().height(150.dp)
                .background(MaterialTheme.colorScheme.surfaceVariant, RoundedCornerShape(topStart = 14.dp, topEnd = 14.dp)),
            contentAlignment = Alignment.Center,
        ) {
            val first = pdf?.first
            if (first != null) {
                Image(
                    first,
                    null,
                    contentScale = ContentScale.Crop,
                    alignment = Alignment.TopCenter,
                    modifier = Modifier.padding(top = 14.dp).width(112.dp).height(136.dp)
                        .border(1.dp, MaterialTheme.colorScheme.outline),
                )
            } else {
                Column(horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    TypeBadge(doc.name)
                    if (doc.info.kind != DocKind.PDF) Small(stringResource(R.string.opens_in_other_app))
                }
            }
        }
        Row(Modifier.padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(doc.name, fontWeight = FontWeight.SemiBold, maxLines = 2, overflow = TextOverflow.MiddleEllipsis)
                val pages = pdf?.pages
                Small(
                    if (pages != null && doc.info.whoSignedPage && pages > 1) {
                        pluralStringResource(R.plurals.pages, pages - 1, pages - 1) + " + " + stringResource(R.string.who_signed_page)
                    } else if (pages != null) {
                        pluralStringResource(R.plurals.pages, pages, pages)
                    } else {
                        ext(doc.name) + " · " + Formatter.formatShortFileSize(context, doc.bytes.size.toLong())
                    },
                )
            }
            ReadButton(onRead)
        }
    }
}

/** 3c: the file alone, as a line. */
@Composable
private fun DocRow(doc: DocFile) {
    Row(
        Modifier.fillMaxWidth().border(1.dp, MaterialTheme.colorScheme.outline, RoundedCornerShape(14.dp)).padding(14.dp),
        horizontalArrangement = Arrangement.spacedBy(14.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        TypeBadge(doc.info.innerName ?: doc.name, 44)
        Text(doc.name, fontWeight = FontWeight.SemiBold, maxLines = 2, overflow = TextOverflow.MiddleEllipsis)
    }
}

/** 3d: a received .cms: the document inside it, and Read it. */
@Composable
private fun CmsCard(doc: DocFile, onRead: () -> Unit) {
    val inner = doc.info.innerName ?: doc.name
    Column(
        Modifier.fillMaxWidth().border(1.dp, MaterialTheme.colorScheme.outline, RoundedCornerShape(14.dp)).padding(14.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Row(horizontalArrangement = Arrangement.spacedBy(14.dp), verticalAlignment = Alignment.CenterVertically) {
            TypeBadge(inner, 44)
            Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(inner, fontWeight = FontWeight.SemiBold, maxLines = 2, overflow = TextOverflow.MiddleEllipsis)
                Small(stringResource(R.string.inside_file, doc.name))
            }
        }
        if (doc.info.output != Output.CANNOT) {
            OutlinedButton(
                onClick = onRead,
                shape = RoundedCornerShape(10.dp),
                modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
            ) { Text(stringResource(R.string.read_it), fontWeight = FontWeight.SemiBold) }
        }
    }
}

@Composable
private fun ReadButton(onClick: () -> Unit) {
    OutlinedButton(onClick = onClick, shape = RoundedCornerShape(10.dp), modifier = Modifier.heightIn(min = 48.dp)) {
        Text(stringResource(R.string.read_it), fontWeight = FontWeight.SemiBold)
    }
}

/** "Already signed by …": who signed before. Checking their signatures is Check's job. */
@Composable
private fun AlreadySigned(s: SignedBy, check: SignerCheck?) {
    val n = LocalNotices.current
    val bad = check != null && !check.valid && check.reason != Reason.NOT_CONFIRMED
    val unsure = check != null && !check.valid && check.reason == Reason.NOT_CONFIRMED
    val (bg, fg) = when {
        bad -> n.badBg to MaterialTheme.colorScheme.error
        unsure -> n.warnBg to n.warnTitle
        check != null -> n.goodBg to n.good
        else -> MaterialTheme.colorScheme.surfaceVariant to MaterialTheme.colorScheme.onSurface
    }
    Row(
        Modifier.fillMaxWidth().background(bg, RoundedCornerShape(12.dp)).padding(14.dp),
        horizontalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        val icon = when {
            bad -> R.drawable.ic_x
            unsure -> R.drawable.ic_clock
            else -> R.drawable.ic_check
        }
        Icon(painterResource(icon), null, tint = fg, modifier = Modifier.size(20.dp))
        Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(stringResource(R.string.already_signed_by, displayName(s.name)), color = fg, fontWeight = FontWeight.SemiBold)
            val date = s.signedMs?.let { stringResource(R.string.signed_on, longDate(it)) }
            val state = when {
                check == null -> null
                check.valid -> stringResource(R.string.valid_short)
                else -> stringResource(reasonTitle(check.reason))
            }
            listOfNotNull(date, state).joinToString(" · ").takeIf { it.isNotEmpty() }?.let { Small(it, if (bad) fg else MaterialTheme.colorScheme.onSurfaceVariant) }
        }
    }
}

/** "Sign with another key": the other keys on the phone. */
@Composable
private fun KeyPicker(keys: List<KeyInfo>, current: KeyInfo, onPick: (KeyInfo) -> Unit) {
    var open by remember { mutableStateOf(false) }
    Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
        TextButton(onClick = { open = true }) { Text(stringResource(R.string.sign_with_another)) }
        DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
            for (k in keys) {
                DropdownMenuItem(
                    text = {
                        Column {
                            Text(displayName(k.name), fontWeight = if (k.id == current.id) FontWeight.SemiBold else FontWeight.Normal)
                            k.company?.let { Small(it) }
                        }
                    },
                    onClick = {
                        open = false
                        onPick(k)
                    },
                )
            }
        }
    }
}
