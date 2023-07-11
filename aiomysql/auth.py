import getpass
import os
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from pymysql import OperationalError, ProgrammingError, InterfaceError
from pymysql.connections import _auth

from .log import logger

try:
    import gssapi
except ImportError:
    gssapi = None

if TYPE_CHECKING:
    from aiomysql.connection import Connection


@dataclass
class AuthInfo:
    password: str
    secure: bool
    server_plugin: str
    conn: "Connection"


class AuthPlugin:
    """
    Abstract base class for authentication plugins.
    """

    name = ""

    async def auth(self, auth_info, data):
        """
        Async generator for authentication process.

        Subclasses should extend this method.

        Many authentication plugins require back-and-forth exchanges
        with the server. These client/server IO - including constructing
        the MySQL protocol packets - is handled by the Connection.
        All this generator needs to do is receive and send plugin specific data.

        Example:
        ```
        class EchoPlugin(AuthPlugin):
            async def auth(self, auth_info, data):
                data_from_server = data
                while True:
                    data_to_server = data_from_server
                    data_from_server = yield data_to_server
        ```

        :param auth_info: Various metadata from the current connection,
            including a reference to the connection itself.
        :type auth_info: AuthInfo
        :param data: Arbitrary data sent by the server.
            This can be, for example, a salt, but it's really up to the
            plugin protocol to choose.
        :type data: bytes
        """
        yield b""

    async def start(
        self, auth_info, data
    ):
        state = self.auth(auth_info, data)
        data = await state.__anext__()
        return data, state


class MysqlNativePassword(AuthPlugin):
    name = "mysql_native_password"

    async def auth(self, auth_info, data):
        yield _auth.scramble_native_password(auth_info.password.encode('latin1'), data)


class CachingSha2Password(AuthPlugin):
    name = "caching_sha2_password"

    async def auth(self, auth_info, data):
        salt = data
        if auth_info.password:
            data = yield _auth.scramble_caching_sha2(
                auth_info.password.encode('latin1'), data
            )
        else:
            data = yield b""

        # magic numbers:
        # 2 - request public key
        # 3 - fast auth succeeded
        # 4 - need full auth

        n = data[0]

        if n == 3:
            logger.debug("caching sha2: succeeded by fast path.")
            yield None
            return

        if n != 4:
            raise OperationalError("caching sha2: Unknown "
                                   "result for fast auth: {}".format(n))

        logger.debug("caching sha2: Trying full auth...")

        if auth_info.secure:
            logger.debug("caching sha2: Sending plain "
                         "password via secure connection")
            yield auth_info.password.encode('latin1') + b'\0'
            return

        if not auth_info.conn.server_public_key:
            auth_info.conn.server_public_key = yield b'\x02'
            logger.debug(auth_info.conn.server_public_key.decode('ascii'))

        yield _auth.sha2_rsa_encrypt(
            auth_info.password.encode('latin1'), salt,
            auth_info.conn.server_public_key
        )


class Sha256Password(AuthPlugin):
    name = "sha256_password"

    async def auth(self, auth_info, data):
        if auth_info.secure:
            logger.debug("sha256: Sending plain password")
            yield auth_info.password.encode('latin1') + b'\0'
            return

        salt = data

        if auth_info.password:
            data = yield b'\1'  # request public key
            auth_info.conn.server_public_key = data
            logger.debug(
                "Received public key:\n%s",
                auth_info.conn.server_public_key.decode('ascii')
            )
            yield _auth.sha2_rsa_encrypt(
                auth_info.password.encode('latin1'), salt,
                auth_info.conn.server_public_key.server_public_key
            )

        else:
            yield b'\0'  # empty password


class MysqlClearPassword(AuthPlugin):
    name = "mysql_clear_password"

    async def auth(self, auth_info, data):
        yield auth_info.password.encode('latin1') + b'\0'


class MysqlOldPassword(AuthPlugin):
    name = "mysql_old_password"

    async def auth(self, auth_info, data):
        yield _auth.scramble_old_password(
            auth_info.password.encode('latin1'),
            data,
        ) + b'\0'


class AuthenticationKerberosClient(AuthPlugin):
    """Mostly borrowed from mysql-connector-python <3"""

    name = "authentication_kerberos_client"

    async def auth(self, auth_info, data):
        if gssapi is None:
            raise ProgrammingError(
                "Module gssapi is required for Kerberos authentication")

        if auth_info.server_plugin != self.name:
            # Wait for AuthSwitchRequest or AuthNextFactor
            data = yield b""

        try:
            spn, realm = self._parse_auth_data(data)
        except struct.error as err:
            raise InterruptedError(f"Invalid authentication data: {err}") from err

        logger.debug("Kerberos Service Principal: %s", spn)
        logger.debug("Kerberos Realm: %s", realm)

        upn = f"{auth_info.conn.user}@{realm}" if auth_info.conn.user else None

        try:
            # Attempt to retrieve credentials from cache file
            creds = gssapi.Credentials(usage="initiate")
            creds_upn = str(creds.name)

            logger.debug("Cached credentials found")
            logger.debug("Cached credentials UPN: %s", creds_upn)

            # Remove the realm from user
            if creds_upn.find("@") != -1:
                creds_user, creds_realm = creds_upn.split("@", 1)
            else:
                creds_user = creds_upn
                creds_realm = None

            upn = f"{auth_info.conn.user}@{realm}" if auth_info.conn.user else creds_upn

            # The user from cached credentials matches with the given user?
            if auth_info.conn.user and auth_info.conn.user != creds_user:
                logger.debug(
                    "The user from cached credentials doesn't match with the "
                    "given user"
                )
                if auth_info.password:
                    creds = self._acquire_cred_with_password(upn, auth_info)
            if creds_realm and creds_realm != realm and auth_info.password:
                creds = self._acquire_cred_with_password(upn, auth_info)
        except gssapi.raw.exceptions.ExpiredCredentialsError as err:
            if upn and auth_info.password:
                creds = self._acquire_cred_with_password(upn, auth_info)
            else:
                raise InterfaceError(f"Credentials has expired: {err}") from err
        except gssapi.raw.misc.GSSError as err:
            if upn and auth_info.password:
                creds = self._acquire_cred_with_password(upn, auth_info)
            else:
                raise InterfaceError(
                    f"Unable to retrieve cached credentials error: {err}"
                ) from err

        auth_info.conn._user = self.get_user_from_credentials(creds)

        flags = (
            gssapi.RequirementFlag.mutual_authentication,
            gssapi.RequirementFlag.extended_error,
            gssapi.RequirementFlag.delegate_to_peer,
        )
        name = gssapi.Name(spn, name_type=gssapi.NameType.kerberos_principal)
        cname = name.canonicalize(gssapi.MechType.kerberos)
        context = gssapi.SecurityContext(
            name=cname, creds=creds, flags=sum(flags), usage="initiate"
        )

        try:
            initial_client_token = context.step()
        except gssapi.raw.misc.GSSError as err:
            raise InterfaceError(f"Unable to initiate security context: {err}") from err

        logger.debug("Initial client token: %s", initial_client_token)

        data = yield initial_client_token

        rcode_size = 5  # Reader size for the response status code
        logger.debug("# Continue with GSSAPI authentication")
        logger.debug("# Response header: %s", data[: rcode_size + 1])
        logger.debug("# Response size: %s", len(data))
        logger.debug("# Negotiate a service request")

        complete = False
        tries = 0

        while not complete and tries < 5:
            logger.debug("%s Attempt %s %s", "-" * 20, tries + 1, "-" * 20)
            logger.debug("<< Server response: %s", data)
            logger.debug("# Response code: %s", data[: rcode_size + 1])
            data = yield context.step(data[rcode_size:])
            logger.debug("Context completed?: %s", context.complete)
            if context.complete:
                break
            tries += 1

        if not context.complete:
            raise InterfaceError(
                f"Unable to fulfill server request after {tries} "
                f"attempts. Last server response: {data}"
            )

    def get_user_from_credentials(self, creds) -> str:
        """Get user from credentials without realm."""
        try:
            user = str(creds.name)
            if user.find("@") != -1:
                user, _ = user.split("@", 1)
            return user
        except gssapi.raw.misc.GSSError:
            return getpass.getuser()

    @staticmethod
    def get_store() -> dict:
        """Get a credentials store dictionary.

        Returns:
            dict: Credentials store dictionary with the krb5 ccache name.

        Raises:
            InterfaceError: If 'KRB5CCNAME' environment variable is empty.
        """
        krb5ccname = os.environ.get(
            "KRB5CCNAME",
            f"/tmp/krb5cc_{os.getuid()}"
            if os.name == "posix"
            else Path("%TEMP%").joinpath("krb5cc"),
        )
        if not krb5ccname:
            raise InterfaceError(
                "The 'KRB5CCNAME' environment variable is set to empty"
            )
        logger.debug("Using krb5 ccache name: FILE:%s", krb5ccname)
        store = {b"ccache": f"FILE:{krb5ccname}".encode("utf-8")}
        return store

    def _acquire_cred_with_password(self, upn, auth_info):
        """Acquire and store credentials through provided password.

        Args:
            upn (str): User Principal Name.

        Returns:
            gssapi.raw.creds.Creds: GSSAPI credentials.
        """
        logger.debug("Attempt to acquire credentials through provided password")
        user = gssapi.Name(upn, gssapi.NameType.user)
        password = auth_info.conn.password.encode("utf-8")

        try:
            acquire_cred_result = gssapi.raw.acquire_cred_with_password(
                user, password, usage="initiate"
            )
            creds = acquire_cred_result.creds
            gssapi.raw.store_cred_into(
                self.get_store(),
                creds=creds,
                mech=gssapi.MechType.kerberos,
                overwrite=True,
                set_default=True,
            )
        except gssapi.raw.misc.GSSError as err:
            raise ProgrammingError(
                f"Unable to acquire credentials with the given password: {err}"
            ) from err
        return creds

    def _parse_auth_data(self, data):
        """Parse authentication data.

        Get the SPN and REALM from the authentication data packet.

        Format:
            SPN string length two bytes <B1> <B2> +
            SPN string +
            UPN realm string length two bytes <B1> <B2> +
            UPN realm string

        Returns:
            tuple: With 'spn' and 'realm'.
        """
        spn_len = struct.unpack("<H", data[:2])[0]
        packet = data[2:]

        spn = struct.unpack(f"<{spn_len}s", packet[:spn_len])[0]
        packet = packet[spn_len:]

        realm_len = struct.unpack("<H", packet[:2])[0]
        realm = struct.unpack(f"<{realm_len}s", packet[2:])[0]

        return spn.decode(), realm.decode()


def get_plugins():
    return [
        MysqlNativePassword(),
        CachingSha2Password(),
        Sha256Password(),
        MysqlClearPassword(),
        MysqlOldPassword(),
        AuthenticationKerberosClient(),
    ]
