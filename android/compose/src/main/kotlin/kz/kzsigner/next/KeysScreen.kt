package kz.kzsigner.next

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.produceState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kz.kzsigner.core.CoreException
import kz.kzsigner.core.KeyInfo
import kz.kzsigner.core.Keys
import kz.kzsigner.core.listKeys
import kz.kzsigner.core.version
import java.io.File
import java.text.DateFormat
import java.util.Date

private sealed interface Loaded {
    data object Loading : Loaded
    data class Ok(val keys: Keys) : Loaded
    data object Failed : Loaded
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun KeysScreen(vault: File) {
    val state by produceState<Loaded>(Loaded.Loading, vault) {
        value = withContext(Dispatchers.IO) {
            try {
                Loaded.Ok(listKeys(vault.path))
            } catch (e: CoreException) {
                Loaded.Failed
            }
        }
    }
    Scaffold(
        topBar = { TopAppBar(title = { Text(stringResource(R.string.your_keys)) }) },
    ) { padding ->
        when (val s = state) {
            Loaded.Loading -> {}
            Loaded.Failed -> Message(padding, stringResource(R.string.cant_read_keys), null)
            is Loaded.Ok -> when {
                s.keys.hidden -> Message(padding, stringResource(R.string.keys_hidden), null)
                s.keys.keys.isEmpty() -> Message(
                    padding,
                    stringResource(R.string.no_keys),
                    stringResource(R.string.no_keys_detail),
                )
                else -> LazyColumn(
                    contentPadding = PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                    modifier = Modifier.padding(padding),
                ) {
                    items(s.keys.keys, key = { it.id }) { KeyCard(it) }
                    item { VersionLine() }
                }
            }
        }
    }
}

@Composable
private fun KeyCard(k: KeyInfo) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(k.name, style = MaterialTheme.typography.titleMedium)
            k.iin?.let { Text(stringResource(R.string.iin, it)) }
            k.company?.let { Text(it) }
            k.bin?.let { Text(stringResource(R.string.bin, it)) }
            val until = DateFormat.getDateInstance(DateFormat.LONG).format(Date(k.expires * 1000))
            Text(
                stringResource(R.string.valid_until, until),
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }
}

@Composable
private fun Message(padding: PaddingValues, title: String, detail: String?) {
    Column(
        Modifier.fillMaxSize().padding(padding).padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp, Alignment.CenterVertically),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(title, style = MaterialTheme.typography.headlineSmall)
        detail?.let { Text(it, style = MaterialTheme.typography.bodyLarge) }
        VersionLine()
    }
}

@Composable
private fun VersionLine() {
    Text(
        stringResource(R.string.version, version()),
        style = MaterialTheme.typography.labelSmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
}
