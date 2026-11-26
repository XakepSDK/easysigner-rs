package kz.kzsigner.ui

import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
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
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kz.kzsigner.AppModel
import kz.kzsigner.Files
import kz.kzsigner.R

/**
 * Screen 4: signed, with NCA's time; Send (the share sheet), Save to phone (the system's
 * save dialog), Done (back to Home).
 */
@Composable
fun SignedScreen(model: AppModel, onDone: () -> Unit) {
    val s = model.signing.signed ?: return
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val savedText = stringResource(R.string.saved)
    val notSaved = stringResource(R.string.not_saved)
    val save = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument(Files.mime(s.name))) { uri ->
        if (uri != null) {
            scope.launch {
                val ok = withContext(Dispatchers.IO) {
                    try {
                        context.contentResolver.openOutputStream(uri)?.use { it.write(s.bytes) } != null
                    } catch (e: Exception) {
                        false
                    }
                }
                Toast.makeText(context, if (ok) savedText else notSaved, Toast.LENGTH_LONG).show()
            }
        }
    }
    val pdf = s.name.endsWith(".pdf", ignoreCase = true)
    Screen(
        onBack = null,
        buttons = {
            Button(
                onClick = { Files.send(context, s.name, s.bytes) },
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier.fillMaxWidth().heightIn(min = 56.dp)
            ) {
                Icon(painterResource(R.drawable.ic_share), null, Modifier.size(22.dp))
                Box(Modifier.width(10.dp))
                Text(stringResource(R.string.send), fontSize = 17.sp, fontWeight = FontWeight.SemiBold)
            }
            SecondButton(stringResource(R.string.save_to_phone)) { save.launch(Files.safe(s.name)) }
            TextButton(onClick = onDone, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) {
                Text(stringResource(R.string.done))
            }
        }
    ) {
        Column(Modifier.fillMaxWidth().padding(top = 24.dp), horizontalAlignment = Alignment.CenterHorizontally) {
            Box(
                Modifier.size(80.dp).background(LocalNotices.current.goodBg, CircleShape),
                contentAlignment = Alignment.Center
            ) {
                Icon(painterResource(R.drawable.ic_check), null, tint = LocalNotices.current.good, modifier = Modifier.size(40.dp))
            }
            Spacer(Modifier.size(20.dp))
            Text(
                stringResource(R.string.signed_title),
                fontSize = 28.sp,
                fontWeight = FontWeight.SemiBold,
                modifier = Modifier.semantics { heading() }
            )
            s.ncaTimeMs?.let {
                Spacer(Modifier.size(10.dp))
                Text(
                    stringResource(R.string.signed_time, dateTime(it)),
                    style = MaterialTheme.typography.bodyLarge,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = TextAlign.Center
                )
            }
        }
        Row(
            Modifier.fillMaxWidth().border(1.dp, MaterialTheme.colorScheme.outline, RoundedCornerShape(14.dp)).padding(16.dp),
            horizontalArrangement = Arrangement.spacedBy(14.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                Modifier.size(48.dp).background(
                    if (pdf) LocalNotices.current.badBg else LocalNotices.current.infoBg,
                    RoundedCornerShape(10.dp)
                ),
                contentAlignment = Alignment.Center
            ) {
                Text(
                    s.name.substringAfterLast('.', "").uppercase().take(4),
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Bold,
                    color = if (pdf) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary
                )
            }
            Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(s.name, fontWeight = FontWeight.SemiBold, maxLines = 2, overflow = TextOverflow.MiddleEllipsis)
                Text(
                    stringResource(R.string.with_signature_inside),
                    color = LocalNotices.current.good,
                    style = MaterialTheme.typography.bodyMedium
                )
            }
        }
        WarnNotice(
            stringResource(R.string.send_file_title),
            stringResource(if (pdf) R.string.send_file_pdf else R.string.send_file_other)
        )
    }
}
