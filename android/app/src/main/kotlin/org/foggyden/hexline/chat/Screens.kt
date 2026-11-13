package org.foggyden.hexline.chat

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalDrawerSheet
import androidx.compose.material3.ModalNavigationDrawer
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.rememberDrawerState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import org.foggyden.hexline.R
import org.foggyden.hexline.core.ChatLine
import org.foggyden.hexline.core.Status
import org.foggyden.hexline.core.User
import org.foggyden.hexline.core.coreVersion

@Composable
fun ConnectScreen(
    error: String?,
    connecting: Boolean,
    onConnect: (url: String, login: String?, password: String?) -> Unit,
) {
    var url by rememberSaveable { mutableStateOf("") }
    var login by rememberSaveable { mutableStateOf("") }
    var password by rememberSaveable { mutableStateOf("") }
    Column(
        Modifier.fillMaxSize().safeDrawingPadding().padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(stringResource(R.string.app_name), style = MaterialTheme.typography.headlineMedium)
        OutlinedTextField(
            url,
            { url = it },
            label = { Text(stringResource(R.string.server_address)) },
            singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            login,
            { login = it },
            label = { Text(stringResource(R.string.login)) },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            password,
            { password = it },
            label = { Text(stringResource(R.string.password)) },
            singleLine = true,
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
            modifier = Modifier.fillMaxWidth(),
        )
        if (error != null) Text(error, color = MaterialTheme.colorScheme.error)
        Button(
            onClick = { onConnect(url.trim(), login.ifBlank { null }, password.ifEmpty { null }) },
            enabled = url.isNotBlank() && !connecting,
        ) { Text(stringResource(if (connecting) R.string.connecting else R.string.connect)) }
        Text(
            stringResource(R.string.core_version, coreVersion()),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.outline,
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ChatScreen(
    state: ChatState,
    onSend: (String) -> Unit,
    onLoadEarlier: () -> Unit,
    onDisconnect: () -> Unit,
) {
    val drawer = rememberDrawerState(androidx.compose.material3.DrawerValue.Closed)
    val scope = rememberCoroutineScope()
    ModalNavigationDrawer(
        drawerState = drawer,
        drawerContent = { ModalDrawerSheet { Roster(state.users, state.selfUid) } },
    ) {
        Scaffold(
            topBar = {
                TopAppBar(
                    title = { Text(state.subject.ifBlank { stringResource(R.string.app_name) }, maxLines = 1) },
                    actions = {
                        TextButton({ scope.launch { drawer.open() } }) {
                            Text(stringResource(R.string.people, state.users.size))
                        }
                        TextButton(onDisconnect) { Text(stringResource(R.string.disconnect)) }
                    },
                )
            },
        ) { padding ->
            Column(Modifier.fillMaxSize().padding(padding).imePadding()) {
                Transcript(state, onLoadEarlier, Modifier.weight(1f))
                Composer(onSend)
            }
        }
    }
}

@Composable
private fun Transcript(
    state: ChatState,
    onLoadEarlier: () -> Unit,
    modifier: Modifier,
) {
    val list = rememberLazyListState()
    // Newest at the bottom, followed as lines arrive.
    LaunchedEffect(state.entries.size) {
        if (state.entries.isNotEmpty()) list.scrollToItem(state.entries.lastIndex)
    }
    val atTop by remember { derivedStateOf { list.firstVisibleItemIndex == 0 } }
    LaunchedEffect(atTop) { if (atTop) onLoadEarlier() }
    LazyColumn(modifier.fillMaxWidth().padding(horizontal = 12.dp), state = list) {
        items(state.entries) { entry ->
            when (entry) {
                is Entry.Line -> Line(entry.line)
                is Entry.Notice ->
                    Text(entry.text, fontStyle = FontStyle.Italic, modifier = Modifier.padding(vertical = 2.dp))
            }
        }
    }
}

@Composable
private fun Line(line: ChatLine) {
    val text =
        when {
            line.deleted -> stringResource(R.string.line_removed)
            line.action -> "* ${line.nick} ${line.text}"
            else -> null
        }
    if (text != null) {
        Text(text, fontStyle = FontStyle.Italic, modifier = Modifier.padding(vertical = 2.dp))
    } else {
        Row(Modifier.padding(vertical = 2.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(line.nick, fontWeight = FontWeight.Bold)
            Text(line.text)
        }
    }
}

@Composable
private fun Composer(onSend: (String) -> Unit) {
    var draft by rememberSaveable { mutableStateOf("") }
    val send = {
        onSend(draft)
        draft = ""
    }
    Row(Modifier.fillMaxWidth().padding(8.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        OutlinedTextField(
            draft,
            { draft = it },
            placeholder = { Text(stringResource(R.string.say_something)) },
            keyboardOptions = KeyboardOptions(imeAction = ImeAction.Send),
            keyboardActions = KeyboardActions(onSend = { send() }),
            modifier = Modifier.weight(1f),
        )
        Button(onClick = send, enabled = draft.isNotBlank()) { Text(stringResource(R.string.send)) }
    }
}

@Composable
private fun Roster(
    users: List<User>,
    selfUid: UShort?,
) {
    Column(Modifier.padding(16.dp)) {
        Text(stringResource(R.string.people, users.size), style = MaterialTheme.typography.titleMedium)
        HorizontalDivider(Modifier.padding(vertical = 8.dp))
        users.sortedBy { it.nick.lowercase() }.forEach { user ->
            val away = user.status != Status.ACTIVE
            Text(
                buildString {
                    append(user.nick)
                    if (user.uid == selfUid) append(" (you)")
                },
                fontWeight = if (user.admin) FontWeight.Bold else FontWeight.Normal,
                fontStyle = if (away) FontStyle.Italic else FontStyle.Normal,
                color = if (away) MaterialTheme.colorScheme.outline else MaterialTheme.colorScheme.onSurface,
                modifier = Modifier.padding(vertical = 4.dp),
            )
        }
    }
}
