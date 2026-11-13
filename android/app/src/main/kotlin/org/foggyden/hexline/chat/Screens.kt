package org.foggyden.hexline.chat

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.consumeWindowInsets
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
import androidx.compose.material3.DrawerValue
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
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
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
    error: Why?,
    connecting: Boolean,
    onConnect: (url: String, login: String?, password: String?) -> Unit,
) {
    var url by rememberSaveable { mutableStateOf("") }
    var login by rememberSaveable { mutableStateOf("") }
    // Not saveable: saved state is written to disk with the task.
    var password by remember { mutableStateOf("") }
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
        if (error != null) {
            Text(
                describe(error),
                color = MaterialTheme.colorScheme.error,
                modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
            )
        }
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

@Composable
private fun describe(why: Why): String =
    when (why) {
        Why.Kicked -> stringResource(R.string.why_kicked)
        Why.Replaced -> stringResource(R.string.why_replaced)
        Why.Lost -> stringResource(R.string.why_lost)
        Why.Unreachable -> stringResource(R.string.why_unreachable)
        Why.WrongPassword -> stringResource(R.string.why_wrong_password)
        Why.Banned -> stringResource(R.string.why_banned)
        Why.Full -> stringResource(R.string.why_full)
        Why.NotUnderstood -> stringResource(R.string.why_not_understood)
        is Why.Refused -> stringResource(R.string.why_refused, why.code)
    }

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ChatScreen(
    state: ChatState,
    onSend: (String) -> Unit,
    onLoadEarlier: () -> Unit,
    onDisconnect: () -> Unit,
) {
    val drawer = rememberDrawerState(DrawerValue.Closed)
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
            Column(
                Modifier
                    .fillMaxSize()
                    .padding(padding)
                    .consumeWindowInsets(padding)
                    .imePadding(),
            ) {
                if (state.link is Link.Reconnecting) {
                    Text(
                        stringResource(R.string.reconnecting),
                        Modifier
                            .fillMaxWidth()
                            .padding(8.dp)
                            .semantics { liveRegion = LiveRegionMode.Polite },
                        style = MaterialTheme.typography.labelLarge,
                    )
                }
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
    // Newest first, laid out from the bottom: a page of history joins at
    // the far end without moving what is being read.
    val newestFirst = state.entries.asReversed()
    val list = rememberLazyListState()
    val newest = newestFirst.firstOrNull()?.key
    // Follow new lines only when already at the newest; a reader scrolled
    // back stays where they are.
    LaunchedEffect(newest) {
        if (list.firstVisibleItemIndex <= 1) list.scrollToItem(0)
    }
    val atOldest by remember {
        derivedStateOf {
            val last =
                list.layoutInfo.visibleItemsInfo
                    .lastOrNull()
                    ?.index ?: 0
            last >= list.layoutInfo.totalItemsCount - 1
        }
    }
    LaunchedEffect(atOldest, state.entries.size) { if (atOldest) onLoadEarlier() }
    LazyColumn(modifier.fillMaxWidth().padding(horizontal = 12.dp), state = list, reverseLayout = true) {
        items(newestFirst, key = { it.key }, contentType = { it::class }) { entry ->
            when (entry) {
                is Entry.Line -> Line(entry.line)
                is Entry.Notice -> Aside(entry.text)
                is Entry.Broadcast -> Aside(stringResource(R.string.broadcast, entry.nick, entry.text))
                is Entry.NotSent -> Aside(stringResource(R.string.not_sent, describe(entry.why)))
            }
        }
    }
}

@Composable
private fun Aside(text: String) {
    Text(text, fontStyle = FontStyle.Italic, modifier = Modifier.padding(vertical = 2.dp))
}

@Composable
private fun Line(line: ChatLine) {
    when {
        line.deleted -> Aside(stringResource(R.string.line_removed))
        line.action -> Aside(stringResource(R.string.action, line.nick, line.text))
        else ->
            Row(
                Modifier.padding(vertical = 2.dp).semantics(mergeDescendants = true) {},
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
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
            singleLine = true,
            keyboardOptions = KeyboardOptions(imeAction = ImeAction.Send),
            keyboardActions = KeyboardActions(onSend = { if (draft.isNotBlank()) send() }),
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
        val away = stringResource(R.string.away)
        val admin = stringResource(R.string.admin)
        val you = stringResource(R.string.you)
        LazyColumn {
            items(users.sortedBy { it.nick.lowercase() }, key = { it.uid.toInt() }) { user ->
                val isAway = user.status != Status.ACTIVE
                Text(
                    if (user.uid == selfUid) "${user.nick} $you" else user.nick,
                    fontWeight = if (user.admin) FontWeight.Bold else FontWeight.Normal,
                    fontStyle = if (isAway) FontStyle.Italic else FontStyle.Normal,
                    color = if (isAway) MaterialTheme.colorScheme.outline else MaterialTheme.colorScheme.onSurface,
                    modifier =
                        Modifier.padding(vertical = 4.dp).semantics {
                            stateDescription = listOfNotNull(away.takeIf { isAway }, admin.takeIf { user.admin }).joinToString()
                        },
                )
            }
        }
    }
}
