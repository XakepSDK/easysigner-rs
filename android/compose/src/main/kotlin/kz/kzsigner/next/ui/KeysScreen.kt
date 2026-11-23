package kz.kzsigner.next.ui

import androidx.appcompat.app.AppCompatDelegate
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.os.LocaleListCompat
import kotlinx.coroutines.launch
import kz.kzsigner.core.CantSign
import kz.kzsigner.core.ChipPrompt
import kz.kzsigner.core.KeyInfo
import kz.kzsigner.core.Unlock
import kz.kzsigner.next.KeysModel
import kz.kzsigner.next.R
import kz.kzsigner.next.hasFingerprint

/** Keys that expire within this many days get a warning. */
private const val WARN_DAYS = 31

/** Screen 7 (and 7b, the removal sheet): the keys on this phone, the language, About. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun KeysScreen(model: KeysModel, onBack: (() -> Unit)?, onAdd: () -> Unit, onAbout: () -> Unit, onEmpty: () -> Unit) {
    val keys = model.keys ?: return
    val scope = rememberCoroutineScope()
    var removing by remember { mutableStateOf<KeyInfo?>(null) }
    val showTitle = stringResource(R.string.prompt_show_title)
    var askedOnce by rememberSaveable { mutableStateOf(false) }
    LaunchedEffect(keys.hidden) {
        if (keys.hidden && !askedOnce) {
            askedOnce = true
            model.unlock(ChipPrompt(showTitle, "", ""))
        }
    }

    Screen(onBack) {
        Title(stringResource(R.string.your_keys))
        if (keys.hidden) {
            Body(stringResource(R.string.keys_hidden))
            SecondButton(stringResource(R.string.show_keys)) {
                scope.launch { model.unlock(ChipPrompt(showTitle, "", "")) }
            }
        }
        for (k in keys.keys) {
            KeyCard(k) { removing = k }
        }
        OutlinedButton(
            onClick = onAdd,
            shape = RoundedCornerShape(12.dp),
            border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline),
            modifier = Modifier.fillMaxWidth().heightIn(min = 56.dp),
        ) {
            Text(stringResource(R.string.add_another), fontSize = 16.sp, fontWeight = FontWeight.SemiBold)
        }
        Column(Modifier.padding(top = 24.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Label(stringResource(R.string.language))
            LanguagePicker()
            TextButton(onClick = onAbout, contentPadding = androidx.compose.foundation.layout.PaddingValues(0.dp)) {
                Text(stringResource(R.string.about_link), style = MaterialTheme.typography.bodyMedium)
            }
        }
    }

    val k = removing
    if (k != null) {
        val sheet = rememberModalBottomSheetState(skipPartiallyExpanded = true)
        ModalBottomSheet(onDismissRequest = { removing = null }, sheetState = sheet) {
            Column(Modifier.padding(horizontal = 20.dp).padding(bottom = 24.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
                Text(
                    stringResource(R.string.remove_title, displayName(k.name)),
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.SemiBold,
                )
                Body(stringResource(R.string.remove_body))
                MainButton(stringResource(R.string.remove), {
                    scope.launch {
                        model.remove(k.id)
                        sheet.hide()
                        removing = null
                        if (model.keys?.keys.isNullOrEmpty() && model.keys?.hidden != true) onEmpty()
                    }
                }, danger = true)
                SecondButton(stringResource(R.string.keep)) {
                    scope.launch {
                        sheet.hide()
                        removing = null
                    }
                }
            }
        }
    }
}

@Composable
private fun KeyCard(k: KeyInfo, onRemove: () -> Unit) {
    val context = LocalContext.current
    Card {
        Text(displayName(k.name), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
        k.iin?.let { Small(stringResource(R.string.iin, it)) }
        k.company?.let { c ->
            Small(if (k.bin != null) c + " · " + stringResource(R.string.bin, k.bin!!) else c)
        }
        val days = daysUntil(k.expiresMs)
        when (k.cantSign) {
            CantSign.EXPIRED -> Bad(stringResource(R.string.expired_on, longDate(k.expiresMs)), stringResource(R.string.expired_detail))
            CantSign.GOST2004 -> Bad(stringResource(R.string.gost2004_short), stringResource(R.string.new_key_detail))
            CantSign.NOT_YET_VALID -> WarnNotice(stringResource(R.string.not_yet_valid), null)
            null -> if (days < WARN_DAYS) {
                val title = if (days <= 0) {
                    stringResource(R.string.expires_today)
                } else {
                    pluralStringResource(R.plurals.expires_in, days.toInt(), days.toInt(), dayMonth(k.expiresMs))
                }
                WarnNotice(title, stringResource(R.string.expires_soon_detail))
            } else {
                Small(stringResource(R.string.valid_until, longDate(k.expiresMs)))
            }
        }
        if (k.cantSign == null) {
            val opens = when (k.unlock) {
                Unlock.FINGERPRINT_OR_SCREEN_LOCK ->
                    if (hasFingerprint(context)) R.string.opens_fingerprint else R.string.opens_screen_lock
                Unlock.FINGERPRINT -> R.string.opens_fingerprint
                Unlock.PASSWORD -> R.string.opens_password
                Unlock.FINGERPRINT_AND_PASSWORD -> R.string.opens_fingerprint_password
            }
            Row(
                Modifier.padding(top = 4.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Icon(painterResource(R.drawable.ic_shield), null, tint = LocalNotices.current.good, modifier = Modifier.size(18.dp))
                Text(stringResource(opens), color = LocalNotices.current.good, style = MaterialTheme.typography.bodyMedium)
            }
        }
        TextButton(onClick = onRemove, contentPadding = androidx.compose.foundation.layout.PaddingValues(0.dp)) {
            Text(stringResource(R.string.remove_from_phone), color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyLarge)
        }
    }
}

@Composable
private fun Bad(title: String, text: String) {
    Notice(title, text, LocalNotices.current.badBg, MaterialTheme.colorScheme.error, MaterialTheme.colorScheme.error)
}

/** The app's language: the phone's, or one of the three (per-app language). */
@Composable
private fun LanguagePicker() {
    val phone = stringResource(R.string.lang_phone)
    val choices = listOf("" to phone, "kk" to "Қазақша", "ru" to "Русский", "en" to "English")
    val current = AppCompatDelegate.getApplicationLocales().toLanguageTags().substringBefore(',').substringBefore('-')
    var open by remember { mutableStateOf(false) }
    Box {
        Surface(
            onClick = { open = true },
            shape = RoundedCornerShape(12.dp),
            border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Row(
                Modifier.heightIn(min = 52.dp).padding(horizontal = 16.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(choices.firstOrNull { it.first == current }?.second ?: phone, Modifier.weight(1f), fontSize = 16.sp)
                Icon(painterResource(R.drawable.ic_down), null)
            }
        }
        DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
            for ((tag, name) in choices) {
                DropdownMenuItem(
                    text = { Text(name) },
                    onClick = {
                        open = false
                        AppCompatDelegate.setApplicationLocales(LocaleListCompat.forLanguageTags(tag))
                    },
                )
            }
        }
    }
}
