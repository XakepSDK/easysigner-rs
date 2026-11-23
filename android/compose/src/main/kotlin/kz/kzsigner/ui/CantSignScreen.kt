package kz.kzsigner.ui

import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kz.kzsigner.core.CantSign
import kz.kzsigner.R

const val EGOV = "https://egov.kz"

/**
 * Screen 3f: the key can't sign (expired, not valid yet, a GOST 2004 key, or, as NCA says
 * when signing, revoked or not NCA's), and how to get a new one. Nothing was added or signed.
 */
@Composable
fun CantSignScreen(reason: CantSign, validFromMs: Long, expiresMs: Long, onBack: () -> Unit, onAddNew: () -> Unit) {
    val context = LocalContext.current
    val (title, body) = when (reason) {
        CantSign.EXPIRED -> stringResource(R.string.cant_sign_expired_title) to
            stringResource(R.string.cant_sign_expired_body, longDate(expiresMs))
        CantSign.NOT_YET_VALID -> stringResource(R.string.cant_sign_future_title) to
            stringResource(R.string.cant_sign_future_body, longDate(validFromMs))
        CantSign.GOST2004 -> stringResource(R.string.cant_sign_gost2004_title) to
            stringResource(R.string.cant_sign_gost2004_body)
        CantSign.REVOKED -> stringResource(R.string.cant_sign_revoked_title) to
            stringResource(R.string.cant_sign_revoked_body)
        CantSign.NOT_RECOGNIZED -> stringResource(R.string.cant_sign_unknown_title) to
            stringResource(R.string.cant_sign_unknown_body)
    }
    Screen(
        onBack,
        buttons = {
            MainButton(stringResource(R.string.open_egov), {
                context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(EGOV)))
            })
            SecondButton(stringResource(R.string.add_new_key), onAddNew)
        },
    ) {
        Column(
            Modifier.fillMaxWidth()
                .background(LocalNotices.current.badBg, RoundedCornerShape(16.dp))
                .padding(22.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Icon(painterResource(R.drawable.ic_key_off), null, tint = MaterialTheme.colorScheme.error, modifier = Modifier.size(34.dp))
            Text(
                title,
                color = MaterialTheme.colorScheme.error,
                fontSize = 26.sp,
                fontWeight = FontWeight.SemiBold,
                modifier = Modifier.semantics { heading() },
            )
            Body(body, MaterialTheme.colorScheme.error)
        }
        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Label(stringResource(R.string.get_new_key))
            Body(stringResource(R.string.get_new_key_body))
        }
    }
}
