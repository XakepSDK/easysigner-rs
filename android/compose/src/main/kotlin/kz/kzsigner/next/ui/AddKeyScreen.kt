package kz.kzsigner.next.ui

import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import kz.kzsigner.core.AddKeyException
import kz.kzsigner.core.ChipPrompt
import kz.kzsigner.core.Unlock
import kz.kzsigner.next.Added
import kz.kzsigner.next.KeyFile
import kz.kzsigner.next.KeysModel
import kz.kzsigner.next.R

/** What went wrong with the last try. */
private enum class Problem { WRONG_PASSWORD, NOT_A_KEY, FAILED }

/**
 * Screens 2 and 2b: choose the key file, type its password, and the chip locks the key on
 * the phone (one fingerprint/PIN prompt). A key that can't sign goes to [onCantSign].
 */
@Composable
fun AddKeyScreen(
    model: KeysModel,
    onBack: (() -> Unit)?,
    onAdded: () -> Unit,
    onCantSign: (AddKeyException.KeyCantSign) -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var file by remember { mutableStateOf<KeyFile?>(null) }
    var password by remember { mutableStateOf("") }
    var shown by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var problem by remember { mutableStateOf<Problem?>(null) }
    var detail by remember { mutableStateOf("") }

    // a key file opened with the app lands here
    LaunchedEffect(model.incoming) {
        model.incoming?.let {
            file = it
            password = ""
            problem = if (it.bytes == null) Problem.NOT_A_KEY else null
            model.incoming = null
        }
    }
    val pick = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) {
            scope.launch {
                val f = model.read(uri)
                file = f
                password = ""
                problem = if (f.bytes == null) Problem.NOT_A_KEY else null
            }
        }
    }
    // key files come as x-pkcs12 or as plain bytes, depending on where they were saved
    val choose = { pick.launch(arrayOf("*/*")) }

    val promptTitle = stringResource(R.string.add_key_title)
    val promptSubtitle = stringResource(R.string.prompt_add_subtitle)
    val alreadyAdded = stringResource(R.string.already_added)
    val submit: () -> Unit = submit@{
        val bytes = file?.bytes ?: return@submit
        if (password.isEmpty() || busy) return@submit
        busy = true
        scope.launch {
            val r = model.add(bytes, password, ChipPrompt(promptTitle, promptSubtitle, ""))
            busy = false
            when (r) {
                Added.Done -> {
                    password = ""
                    onAdded()
                }
                Added.Cancelled -> {}
                is Added.Refused -> when (val e = r.why) {
                    is AddKeyException.WrongPassword -> problem = Problem.WRONG_PASSWORD
                    is AddKeyException.NotAKey -> problem = Problem.NOT_A_KEY
                    is AddKeyException.KeyCantSign -> onCantSign(e)
                    is AddKeyException.AlreadyAdded -> {
                        Toast.makeText(context, alreadyAdded, Toast.LENGTH_LONG).show()
                        onAdded()
                    }
                    is AddKeyException.Failed -> {
                        problem = Problem.FAILED
                        detail = e.detail
                    }
                    is AddKeyException.Cancelled -> {}
                }
            }
        }
    }

    val f = file
    if (f == null) {
        Screen(onBack, buttons = { MainButton(stringResource(R.string.choose_key_file), choose) }) {
            // 2c: a document shared before any key: it waits
            model.document?.let { InfoNotice(stringResource(R.string.shared_needs_key, it.name), R.drawable.ic_file) }
            Title(stringResource(R.string.add_key_title))
            Body(stringResource(R.string.choose_key_hint))
            Small(stringResource(R.string.no_key_yet))
        }
        return
    }
    val wrong = problem == Problem.WRONG_PASSWORD
    Screen(
        onBack,
        buttons = {
            MainButton(
                stringResource(if (wrong) R.string.try_again else R.string.continue_),
                submit,
                enabled = f.bytes != null && problem != Problem.NOT_A_KEY && password.isNotEmpty(),
                busy = busy,
            )
        },
    ) {
        Title(stringResource(R.string.add_key_title))
        Body(
            stringResource(
                when {
                    model.newKeyUnlock != Unlock.PASSWORD -> R.string.add_key_once_device
                    model.screenLock -> R.string.add_key_once_nochip
                    else -> R.string.add_key_once_password
                },
            ),
        )
        FileCard(f.name, if (problem == Problem.NOT_A_KEY) stringResource(R.string.not_a_key) else null, choose)
        if (problem == Problem.NOT_A_KEY) return@Screen
        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
            OutlinedTextField(
                value = password,
                onValueChange = {
                    password = it
                    if (problem == Problem.FAILED) problem = null
                },
                label = { Text(stringResource(R.string.key_password)) },
                singleLine = true,
                isError = wrong,
                visualTransformation = if (shown) VisualTransformation.None else PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, imeAction = ImeAction.Done),
                keyboardActions = KeyboardActions(onDone = { submit() }),
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
            when (problem) {
                Problem.WRONG_PASSWORD -> Small(stringResource(R.string.wrong_password), MaterialTheme.colorScheme.error)
                Problem.FAILED -> Small(stringResource(R.string.add_failed, detail), MaterialTheme.colorScheme.error)
                else -> Small(stringResource(R.string.key_password_hint))
            }
        }
        if (wrong) {
            if (password.any { it in 'Ѐ'..'ӿ' }) {
                WarnNotice(stringResource(R.string.keyboard_title), stringResource(R.string.keyboard_detail))
            }
            Small(stringResource(R.string.forgot_password))
        } else {
            InfoNotice(
                stringResource(
                    when {
                        model.newKeyUnlock != Unlock.PASSWORD -> R.string.key_stays_device
                        model.screenLock -> R.string.key_stays_nochip
                        else -> R.string.key_stays_password
                    },
                ),
            )
        }
    }
}

/** The chosen key file; tapping it chooses another. */
@Composable
private fun FileCard(name: String, error: String?, onClick: () -> Unit) {
    Surface(
        shape = RoundedCornerShape(12.dp),
        color = MaterialTheme.colorScheme.surfaceVariant,
        border = BorderStroke(1.dp, if (error != null) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.outline),
        modifier = Modifier.fillMaxWidth().clickable(role = Role.Button, onClick = onClick),
    ) {
        Row(
            Modifier.padding(16.dp),
            horizontalArrangement = Arrangement.spacedBy(14.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(painterResource(R.drawable.ic_file), null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(26.dp))
            Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(name, fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.MiddleEllipsis)
                Small(error ?: stringResource(R.string.choose_another), if (error != null) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}
