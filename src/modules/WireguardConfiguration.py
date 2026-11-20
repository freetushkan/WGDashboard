"""
WireGuard Configuration
"""
from typing import Any

import sqlalchemy, random, shutil, configparser, ipaddress, os, subprocess, time, re, uuid, psutil, traceback, threading, functools
from zipfile import ZipFile
from datetime import datetime, timedelta
from itertools import islice
from flask import current_app

from .DatabaseConnection import ConnectionString
from .DashboardConfig import DashboardConfig
from .Peer import Peer
from .PeerJobs import PeerJobs
from .PeerShareLinks import PeerShareLinks
from .Utilities import StringToBoolean, \
    GenerateWireguardPublicKey, \
    RegexMatch, \
    ValidateDNSAddress, \
    ValidateEndpointAllowedIPs, \
    CheckAddress, \
    CheckPeerKey, \
    RenderSandboxedTemplate
from .WireguardConfigurationInfo import WireguardConfigurationInfo, PeerGroupsClass
from .DashboardWebHooks import DashboardWebHooks


def peersLocked(func):
    """
    Serialize everything that touches peers of one configuration.
    Request threads and the background thread call getPeers()/addPeers()/deletePeers()
    concurrently; without this, getPeers() could re-read the .conf file between
    a DB commit and the following `wg-quick save` and resurrect just deleted peers
    as nameless "Untitled" rows without private keys.
    """
    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        with self.peersLock:
            return func(self, *args, **kwargs)
    return wrapper


class WireguardConfiguration:
    class InvalidConfigurationFileException(Exception):
        def __init__(self, m):
            self.message = m

        def __str__(self):
            return self.message

    def __init__(self, DashboardConfig: DashboardConfig, 
                 AllPeerJobs: PeerJobs,
                 AllPeerShareLinks: PeerShareLinks,
                 DashboardWebHooks: DashboardWebHooks,
                 name: str = None,
                 data: dict = None,
                 backup: dict = None,
                 startup: bool = False,
                 wg: bool = True
                 ):
        self.peersLock = threading.RLock()
        self.__configPeerIds: set[str] | None = None
        self.Peers = []
        self.__parser: configparser.ConfigParser = configparser.RawConfigParser(strict=False)
        self.__parser.optionxform = str
        self.__configFileModifiedTime = None
        self.Status: bool = False
        self.Name: str = ""
        self.PrivateKey: str = ""
        self.PublicKey: str = ""
        self.ListenPort: str = ""
        self.Address: str = ""
        self.DNS: str = ""
        self.Table: str = ""
        self.MTU: str = ""
        self.PreUp: str = ""
        self.PostUp: str = ""
        self.PreDown: str = ""
        self.PostDown: str = ""
        self.SaveConfig: bool = True
        self.Name = name
        self.Protocol = "wg" if wg else "awg"
        self.AllPeerJobs = AllPeerJobs
        self.DashboardConfig = DashboardConfig
        self.DashboardConfig.EnsureDatabaseIntegrity({self.Name: self})
        self.AllPeerShareLinks = AllPeerShareLinks
        self.DashboardWebHooks = DashboardWebHooks
        self.configPath = os.path.join(self.__getProtocolPath(), f'{self.Name}.conf')
        self.engine: sqlalchemy.Engine = sqlalchemy.create_engine(ConnectionString("wgdashboard"))
        self.metadata: sqlalchemy.MetaData = sqlalchemy.MetaData()
        self.dbType = self.DashboardConfig.GetConfig("Database", "type")[1]

        if name is not None:
            if data is not None and "Backup" in data.keys():
                db = self.__importDatabase(
                    os.path.join(
                        self.__getProtocolPath(),
                        'WGDashboard_Backup',
                        data["Backup"].replace(".conf", ".sql")), True)
            else:
                self.createDatabase()

            self.__parseConfigurationFile()
            self.__initPeersList()
        else:
            self.Name = data["ConfigurationName"]
            self.configPath = os.path.join(self.__getProtocolPath(), f'{self.Name}.conf')

            for i in dir(self):
                if str(i) in data.keys():
                    if isinstance(getattr(self, i), bool):
                        setattr(self, i, StringToBoolean(data[i]))
                    else:
                        setattr(self, i, str(data[i]))

            self.__parser["Interface"] = {
                "PrivateKey": self.PrivateKey,
                "Address": self.Address,
                "ListenPort": self.ListenPort,
                "PreUp": f"{self.PreUp}",
                "PreDown": f"{self.PreDown}",
                "PostUp": f"{self.PostUp}",
                "PostDown": f"{self.PostDown}",
                "SaveConfig": "true"
            }

            if self.Protocol == 'awg':
                values = {
                    "Jc": self.Jc,
                    "Jmin": self.Jmin,
                    "Jmax": self.Jmax,
                    "S1": self.S1,
                    "S2": self.S2,
                    "S3": self.S3,
                    "S4": self.S4,
                    "H1": self.H1,
                    "H2": self.H2,
                    "H3": self.H3,
                    "H4": self.H4,
                    "I1": self.I1,
                    "I2": self.I2,
                    "I3": self.I3,
                    "I4": self.I4,
                    "I5": self.I5,
                    "HeaderProtectionKey": self.HeaderProtectionKey,
                    "ContentPaddingAddition": self.ContentPaddingAddition,
                    "RekeyAfterTime": self.RekeyAfterTime,
                    "RekeyTimeout": self.RekeyTimeout,
                    "RejectAfterTime": self.RejectAfterTime,
                    "KeepaliveTimeout": self.KeepaliveTimeout,
                    "MaxHandshakeAttempts": self.MaxHandshakeAttempts,
                    "RandomTrailers": self.RandomTrailers,
                    "DisableCookies": self.DisableCookies,
                    "J1": self.J1,
                    "J2": self.J2,
                    "J3": self.J3,
                    "Itime": self.Itime
                }
                for key, value in values.items():
                    if value != None and str(value).strip():
                        self.__parser["Interface"][key] = str(value)

            if "Backup" not in data.keys():
                self.createDatabase()
                with open(self.configPath, "w+") as configFile:
                    self.__parser.write(configFile)
                    current_app.logger.info(f"Configuration file {self.configPath} created")
                self.__initPeersList()

        if not os.path.exists(os.path.join(self.__getProtocolPath(), 'WGDashboard_Backup')):
            os.mkdir(os.path.join(self.__getProtocolPath(), 'WGDashboard_Backup'))

        current_app.logger.info(f"Initialized Configuration: {name}")
        self.__dumpDatabase()
        if self.getAutostartStatus() and not self.getStatus() and startup:
            status, ext = self.toggleConfiguration()
            if not status:
                current_app.logger.error(f"Failed to autostart configuration: {name}. Reason: {ext}")
            else:
                current_app.logger.info(f"Autostart Configuration: {name}")
            
        self.configurationInfo: WireguardConfigurationInfo | None = None
        configurationInfoJson = self.readConfigurationInfo()
        if not configurationInfoJson:
            self.configurationInfo = WireguardConfigurationInfo(**{})
            self.initConfigurationInfo()
        else:
            self.configurationInfo = WireguardConfigurationInfo.model_validate_json(configurationInfoJson.get("Info"))
        
        if self.Status:
            self.addAutostart()

    def __getProtocolPath(self) -> str:
        _, path = self.DashboardConfig.GetConfig("Server", "wg_conf_path") if self.Protocol == "wg" \
            else self.DashboardConfig.GetConfig("Server", "awg_conf_path")
        return path

    def __initPeersList(self):
        self.Peers: list[Peer] = []
        self.getPeers()
        self.getRestrictedPeersList()

    def getRawConfigurationFile(self):
        return open(self.configPath, 'r').read()

    def updateRawConfigurationFile(self, newRawConfiguration):
        backupStatus, backup = self.backupConfigurationFile()
        if not backupStatus:
            return False, "Cannot create backup"

        if self.Status:
            self.toggleConfiguration()

        with open(self.configPath, 'w') as f:
            f.write(newRawConfiguration)

        status, err = self.toggleConfiguration()
        if not status:
            restoreStatus = self.restoreBackup(backup['filename'])
            current_app.logger.error(f"Backup restore status: {restoreStatus}")
            self.toggleConfiguration()
            return False, err
        return True, None

    def __parseConfigurationFile(self):
        with open(self.configPath, 'r') as f:
            original = [l.rstrip("\n") for l in f.readlines()]
            try:
                start = original.index("[Interface]")

                # Clean
                for i in range(start, len(original)):
                    if original[i] == "[Peer]":
                        break
                    split = re.split(r'\s*=\s*', original[i], 1)
                    if len(split) == 2:
                        key = split[0]
                        if key in dir(self):
                            if isinstance(getattr(self, key), bool):
                                setattr(self, key, False)
                            else:
                                setattr(self, key, "")

                # Set
                for i in range(start, len(original)):
                    if original[i] == "[Peer]":
                        break
                    split = re.split(r'\s*=\s*', original[i], 1)
                    if len(split) == 2:
                        key = split[0]
                        value = split[1]
                        if key in dir(self):
                            if isinstance(getattr(self, key), bool):
                                setattr(self, key, StringToBoolean(value))
                            else:
                                if len(getattr(self, key)) > 0:
                                    setattr(self, key, f"{getattr(self, key)}, {value}")
                                else:
                                    setattr(self, key, value)
            except ValueError as e:
                raise self.InvalidConfigurationFileException(
                    "[Interface] section not found in " + self.configPath)
            if self.PrivateKey:
                self.PublicKey = self.__getPublicKey()
            self.Status = self.getStatus()

    def __dropDatabase(self):
        existingTables = [self.Name, f'{self.Name}_restrict_access', f'{self.Name}_transfer', f'{self.Name}_deleted', f'{self.Name}_history_endpoint']
        try:
            with self.engine.begin() as conn:
                for name in existingTables:
                    table = sqlalchemy.Table(name, sqlalchemy.MetaData())
                    conn.execute(
                        sqlalchemy.schema.DropTable(table, if_exists=True)
                    )
        except Exception:
            current_app.logger.exception("Dropping table failed")
            return False
        return True

    def createDatabase(self, dbName = None):
        def generate_column_obj():
            return [
                sqlalchemy.Column('id', sqlalchemy.String(255), nullable=False, primary_key=True),
                sqlalchemy.Column('private_key', sqlalchemy.String(255)),
                sqlalchemy.Column('DNS', sqlalchemy.Text),
                sqlalchemy.Column('endpoint_allowed_ip', sqlalchemy.Text),
                sqlalchemy.Column('name', sqlalchemy.Text),
                sqlalchemy.Column('total_receive', sqlalchemy.Float),
                sqlalchemy.Column('total_sent', sqlalchemy.Float),
                sqlalchemy.Column('total_data', sqlalchemy.Float),
                sqlalchemy.Column('endpoint', sqlalchemy.String(255)),
                sqlalchemy.Column('status', sqlalchemy.String(255)),
                sqlalchemy.Column('latest_handshake', sqlalchemy.String(255)),
                sqlalchemy.Column('allowed_ip', sqlalchemy.String(255)),
                sqlalchemy.Column('cumu_receive', sqlalchemy.Float),
                sqlalchemy.Column('cumu_sent', sqlalchemy.Float),
                sqlalchemy.Column('cumu_data', sqlalchemy.Float),
                sqlalchemy.Column('mtu', sqlalchemy.Integer),
                sqlalchemy.Column('keepalive', sqlalchemy.Integer),
                sqlalchemy.Column('notes', sqlalchemy.Text),
                sqlalchemy.Column('remote_endpoint', sqlalchemy.String(255)),
                sqlalchemy.Column('preshared_key', sqlalchemy.String(255))
            ]

        if dbName is None:
            dbName = self.Name

        self.peersTable = sqlalchemy.Table(
            f'{dbName}', self.metadata, *generate_column_obj(), extend_existing=True
        )

        self.peersRestrictedTable = sqlalchemy.Table(
            f'{dbName}_restrict_access', self.metadata, *generate_column_obj(), extend_existing=True
        )

        self.peersDeletedTable = sqlalchemy.Table(
            f'{dbName}_deleted', self.metadata, *generate_column_obj(), extend_existing=True
        )

        if self.DashboardConfig.GetConfig("Database", "type")[1] == 'sqlite':
            time_col_type = sqlalchemy.DATETIME
        else:
            time_col_type = sqlalchemy.TIMESTAMP

        self.peersTransferTable = sqlalchemy.Table(
            f'{dbName}_transfer', self.metadata,
            sqlalchemy.Column('id', sqlalchemy.String(255), nullable=False),
            sqlalchemy.Column('total_receive', sqlalchemy.Float),
            sqlalchemy.Column('total_sent', sqlalchemy.Float),
            sqlalchemy.Column('total_data', sqlalchemy.Float),
            sqlalchemy.Column('cumu_receive', sqlalchemy.Float),
            sqlalchemy.Column('cumu_sent', sqlalchemy.Float),
            sqlalchemy.Column('cumu_data', sqlalchemy.Float),
            sqlalchemy.Column('time', time_col_type, server_default=sqlalchemy.func.now()),
            extend_existing=True
        )
        
        self.peersHistoryEndpointTable = sqlalchemy.Table(
            f'{dbName}_history_endpoint', self.metadata,
            sqlalchemy.Column('id', sqlalchemy.String(255), nullable=False),
            sqlalchemy.Column('endpoint', sqlalchemy.String(255), nullable=False),
            sqlalchemy.Column('time', time_col_type),
            extend_existing=True
        )
        
        self.infoTable = sqlalchemy.Table(
            'ConfigurationsInfo', self.metadata,
            sqlalchemy.Column('ID', sqlalchemy.String(255), primary_key=True),
            sqlalchemy.Column('Info', sqlalchemy.Text),
            extend_existing=True
        )

        self.metadata.create_all(self.engine)

    def __dumpDatabase(self):
        with self.engine.connect() as conn:
            tables = [self.peersTable, self.peersRestrictedTable, self.peersTransferTable, self.peersDeletedTable]
            for i in tables:
                rows = conn.execute(i.select()).mappings().fetchall()
                for row in rows:
                    insert_stmt = i.insert().values(dict(row))
                    yield str(
                        insert_stmt.compile(
                            dialect=self.engine.dialect,
                            compile_kwargs={"literal_binds": True},
                        )
                    )

    def __importDatabase(self, sqlFilePath, restore = False) -> bool:
        if not restore:
            if not self.__dropDatabase():
                raise RuntimeError(
                    f"Failed to drop tables for configuration {self.Name}"
                )
        self.createDatabase()
        if not os.path.exists(sqlFilePath):
            return False
        with self.engine.begin() as conn:
            with open(sqlFilePath, 'r') as f:
                for l in f.readlines():
                    l = l.rstrip("\n")
                    if len(l) > 0:
                        conn.execute(sqlalchemy.text(l))
        return True

    def __getPublicKey(self) -> str:
        return GenerateWireguardPublicKey(self.PrivateKey)[1]

    def getStatus(self) -> bool:
        self.Status = self.Name in psutil.net_if_addrs().keys()
        return self.Status

    def getAutostartStatus(self):
        s, d = self.DashboardConfig.GetConfig("WireGuardConfiguration", "autostart")
        return self.Name in d
    
    def addAutostart(self):
        s, d = self.DashboardConfig.GetConfig("WireGuardConfiguration", "autostart")
        if self.Name not in d:
            d.append(self.Name)
            self.DashboardConfig.SetConfig("WireGuardConfiguration", "autostart", d)
    
    def removeAutostart(self):
        s, d = self.DashboardConfig.GetConfig("WireGuardConfiguration", "autostart")
        if self.Name in d:
            d.remove(self.Name)
            self.DashboardConfig.SetConfig("WireGuardConfiguration", "autostart", d)

    def _newPeer(self, tableData) -> Peer:
        """Peer object factory, overridden by AmneziaConfiguration"""
        return Peer(tableData, self)

    def getRestrictedPeers(self):
        with self.engine.connect() as conn:
            restricted = conn.execute(self.peersRestrictedTable.select()).mappings().fetchall()
        self.RestrictedPeers = [self._newPeer(i) for i in restricted]

    def configurationFileChanged(self) :
        mt = os.path.getmtime(self.configPath)
        changed = self.__configFileModifiedTime is None or self.__configFileModifiedTime != mt
        self.__configFileModifiedTime = mt
        return changed

    def __parseConfigurationPeers(self) -> list[dict]:
        with open(self.configPath, 'r') as configFile:
            content = configFile.read().split('\n')
        if "[Peer]" not in content:
            return []
        p = []
        pCounter = -1
        content = content[content.index("[Peer]"):]
        for i in content:
            if not RegexMatch("#(.*)", i) and not RegexMatch(";(.*)", i):
                if i == "[Peer]":
                    pCounter += 1
                    p.append({})
                    p[pCounter]["name"] = ""
                else:
                    if len(i) > 0:
                        split = re.split(r'\s*=\s*', i, 1)
                        if len(split) == 2:
                            p[pCounter][split[0]] = split[1]

            if RegexMatch("#Name# = (.*)", i):
                split = re.split(r'\s*=\s*', i, 1)
                if len(split) == 2:
                    p[pCounter]["name"] = split[1]
        return [i for i in p if "PublicKey" in i.keys()]

    def __defaultPeerData(self, i: dict) -> dict:
        mtu = self.DashboardConfig.GetConfig("Peers", "peer_mtu")[1]
        keepalive = self.DashboardConfig.GetConfig("Peers", "peer_keep_alive")[1]
        return {
            "id": i['PublicKey'],
            "private_key": "",
            "DNS": self.DashboardConfig.GetConfig("Peers", "peer_global_DNS")[1],
            "endpoint_allowed_ip": self.DashboardConfig.GetConfig("Peers", "peer_endpoint_allowed_ip")[1],
            "name": i.get("name"),
            "total_receive": 0,
            "total_sent": 0,
            "total_data": 0,
            "endpoint": "N/A",
            "status": "stopped",
            "latest_handshake": "N/A",
            "allowed_ip": i.get("AllowedIPs", "N/A"),
            "cumu_receive": 0,
            "cumu_sent": 0,
            "cumu_data": 0,
            "mtu": mtu if len(mtu) > 0 else None,
            "keepalive": keepalive if len(keepalive) > 0 else None,
            "notes": "",
            "remote_endpoint": self.DashboardConfig.GetConfig("Peers", "remote_endpoint")[1],
            "preshared_key": i["PresharedKey"] if "PresharedKey" in i.keys() else ""
        }

    @peersLocked
    def getPeers(self):
        """
        The .conf file is the source of truth for which peers exist. Database rows of
        peers that are not in the file (left over from interrupted operations) are
        never listed; they are only reported in the log.
        """
        if self.configurationFileChanged():
            tmpList = []
            try:
                configPeers = self.__parseConfigurationPeers()
                if len(configPeers) == 0:
                    current_app.logger.info(f"{self.Name} config has no [Peer] section")
                with self.engine.begin() as conn:
                    for i in configPeers:
                        tempPeer = conn.execute(
                            self.peersTable.select().where(
                                self.peersTable.columns.id == i['PublicKey']
                            )
                        ).mappings().fetchone()
                        if tempPeer is None:
                            tempPeer = self.__defaultPeerData(i)
                            current_app.logger.warning(
                                f"{self.Name}: peer {i['PublicKey']} found in the configuration file but not in the database, importing it without a private key")
                            conn.execute(
                                self.peersTable.insert().values(tempPeer)
                            )
                        elif tempPeer['allowed_ip'] != i.get("AllowedIPs", "N/A"):
                            conn.execute(
                                self.peersTable.update().values({
                                    "allowed_ip": i.get("AllowedIPs", "N/A")
                                }).where(
                                    self.peersTable.columns.id == i['PublicKey']
                                )
                            )
                            tempPeer = dict(tempPeer)
                            tempPeer['allowed_ip'] = i.get("AllowedIPs", "N/A")
                        tmpList.append(self._newPeer(tempPeer))
                self.__configPeerIds = set(map(lambda x: x['PublicKey'], configPeers))
                self.Peers = tmpList
                self.__reportOrphanPeers()
            except Exception as e:
                # Parse again on the next call instead of trusting a half-read file
                self.__configFileModifiedTime = None
                current_app.logger.exception(f"{self.Name} getPeers() Error")
        else:
            with self.engine.connect() as conn:
                existingPeers = conn.execute(self.peersTable.select()).mappings().fetchall()
            if self.__configPeerIds is not None:
                existingPeers = [i for i in existingPeers if i['id'] in self.__configPeerIds]
            self.Peers = [self._newPeer(i) for i in existingPeers]

    def __reportOrphanPeers(self):
        with self.engine.connect() as conn:
            dbIds = set(conn.execute(sqlalchemy.select(self.peersTable.c.id)).scalars().all())
        orphans = sorted(dbIds - self.__configPeerIds)
        if orphans and orphans != getattr(self, '_orphansReported', None):
            current_app.logger.warning(
                f"{self.Name}: {len(orphans)} peer(s) exist in the database but not in the configuration file "
                f"and are hidden: {', '.join(orphans)}")
        self._orphansReported = orphans

    def logPeersTraffic(self):
        with self.engine.begin() as conn:
            for tempPeer in self.Peers:
                if tempPeer.status == "running":
                    conn.execute(
                        self.peersTransferTable.insert().values({
                            "id": tempPeer.id,
                            "total_receive": tempPeer.total_receive,
                            "total_sent": tempPeer.total_sent,
                            "total_data": tempPeer.total_data,
                            "cumu_sent": tempPeer.cumu_sent,
                            "cumu_receive": tempPeer.cumu_receive,
                            "cumu_data": tempPeer.cumu_data,
                            "time": datetime.now()
                        })
                    )
    
    def logPeersHistoryEndpoint(self):
        with self.engine.begin() as conn:
            for tempPeer in self.Peers:
                if tempPeer.status == "running":
                    endpoint = tempPeer.endpoint.rsplit(":", 1)    
                    if len(endpoint) == 2 and len(endpoint[0]) > 0:
                        exist = conn.execute(
                            self.peersHistoryEndpointTable.select().where(
                                sqlalchemy.and_(
                                    self.peersHistoryEndpointTable.c.id == tempPeer.id,
                                    self.peersHistoryEndpointTable.c.endpoint == endpoint[0]
                                )
                            )
                        ).mappings().fetchone()
                        if not exist:
                            conn.execute(
                                self.peersHistoryEndpointTable.insert().values({
                                    "id": tempPeer.id,
                                    "endpoint": endpoint[0],
                                    "time": datetime.now()
                                })
                            )

    def __wgSetPeer(self, publicKey: str, allowedIPs: str, presharedKey: str):
        presharedKeyExist = len(presharedKey) > 0
        uid = str(uuid.UUID(int=random.Random().getrandbits(128), version=4))
        if presharedKeyExist:
            with open(uid, "w+") as f:
                f.write(presharedKey)
        try:
            command = [self.Protocol, "set", self.Name, "peer", publicKey, "allowed-ips", allowedIPs,
                       "preshared-key", uid if presharedKeyExist else "/dev/null"]
            subprocess.check_output(command, stderr=subprocess.STDOUT)
        finally:
            if presharedKeyExist and os.path.exists(uid):
                os.remove(uid)

    def __wgRemovePeer(self, publicKey: str) -> bool:
        try:
            subprocess.check_output([self.Protocol, "set", self.Name, "peer", publicKey, "remove"],
                                    stderr=subprocess.STDOUT)
            return True
        except subprocess.CalledProcessError as e:
            current_app.logger.error(f"{self.Name}: failed to remove peer {publicKey}: {e.output.decode(errors='replace').strip()}")
            return False

    @peersLocked
    def addPeers(self, peers: list) -> tuple[bool, list, str]:
        result = {
            "message": None,
            "peers": []
        }
        cleanedAllowedIPs = {}
        for p in peers:
            newAllowedIPs = p['allowed_ip'].replace(" ", "")
            if not CheckAddress(newAllowedIPs):
                return False, [], "Allowed IPs entry format is incorrect"
            if not CheckPeerKey(p["id"]):
                return False, [], "Peer key format is incorrect"
            cleanedAllowedIPs[p["id"]] = newAllowedIPs

        self.getPeers()
        for p in peers:
            if self.searchPeer(p['id'])[0]:
                return False, [], f"Peer {p['id']} already exists"

        applied = []
        try:
            # Database first: if anything below fails, a peer that is in the .conf
            # file always has its row (and private key) in the database
            with self.engine.begin() as conn:
                for i in peers:
                    # Stale row of a peer that is not in the configuration file anymore
                    conn.execute(
                        self.peersTable.delete().where(self.peersTable.columns.id == i['id'])
                    )
                    newPeer = {
                        "id": i['id'],
                        "private_key": i['private_key'],
                        "DNS": i['DNS'],
                        "endpoint_allowed_ip": i['endpoint_allowed_ip'],
                        "name": i['name'],
                        "total_receive": 0,
                        "total_sent": 0,
                        "total_data": 0,
                        "endpoint": "N/A",
                        "status": "stopped",
                        "latest_handshake": "N/A",
                        "allowed_ip": i.get("allowed_ip", "N/A"),
                        "cumu_receive": 0,
                        "cumu_sent": 0,
                        "cumu_data": 0,
                        "mtu": i['mtu'],
                        "keepalive": i['keepalive'],
                        "notes": i.get("notes", ""),
                        "remote_endpoint": self.DashboardConfig.GetConfig("Peers", "remote_endpoint")[1],
                        "preshared_key": i["preshared_key"]
                    }
                    conn.execute(
                        self.peersTable.insert().values(newPeer)
                    )
            for p in peers:
                self.__wgSetPeer(p['id'], cleanedAllowedIPs[p["id"]], p['preshared_key'])
                applied.append(p['id'])

            status, msg = self.__wgSave()
            if not status:
                raise RuntimeError("Failed to save configuration through WireGuard")

            self.getPeers()
            for p in peers:
                p = self.searchPeer(p['id'])
                if p[0]:
                    result['peers'].append(p[1])
            self.DashboardWebHooks.RunWebHook("peer_created", {
                "configuration": self.Name,
                "peers": list(map(lambda k : k['id'], peers))
            })
        except Exception as e:
            current_app.logger.exception("Add peers error")
            # Roll back what did not make it into WireGuard, keep the rest consistent
            try:
                notApplied = [p['id'] for p in peers if p['id'] not in applied]
                if notApplied:
                    with self.engine.begin() as conn:
                        conn.execute(
                            self.peersTable.delete().where(self.peersTable.columns.id.in_(notApplied))
                        )
                if applied:
                    self.__wgSave()
                self.getPeers()
            except Exception:
                current_app.logger.exception("Add peers rollback error")
            return False, [], "Internal server error"
        return True, result['peers'], ""

    def searchPeer(self, publicKey):
        for i in self.Peers:
            if i.id == publicKey:
                return True, i
        return False, None

    @peersLocked
    def allowAccessPeers(self, listOfPublicKeys) -> tuple[bool, str]:
        if not self.getStatus():
            self.toggleConfiguration()

        restrictedPeers = []
        with self.engine.connect() as conn:
            for i in listOfPublicKeys:
                restrictedPeer = conn.execute(
                    self.peersRestrictedTable.select().where(self.peersRestrictedTable.columns.id == i)
                ).mappings().fetchone()
                if restrictedPeer is None:
                    return False, "Failed to allow access of peer " + i
                if not CheckAddress(restrictedPeer['allowed_ip'].replace(" ", "")):
                    return False, "Allowed IPs entry format is incorrect"
                if not CheckPeerKey(restrictedPeer["id"]):
                    return False, "Peer key format is incorrect"
                restrictedPeers.append(restrictedPeer)

        # Move rows first so that a peer appearing in the .conf file always has its row
        with self.engine.begin() as conn:
            for restrictedPeer in restrictedPeers:
                stmt = self.peersRestrictedTable.select().where(
                    self.peersRestrictedTable.columns.id == restrictedPeer['id']
                )
                conn.execute(
                    self.peersTable.delete().where(self.peersTable.columns.id == restrictedPeer['id'])
                )
                conn.execute(
                    self.peersTable.insert().from_select(
                        [c.name for c in self.peersTable.columns],
                        stmt
                    )
                )
                conn.execute(
                    self.peersRestrictedTable.delete().where(
                        self.peersRestrictedTable.columns.id == restrictedPeer['id']
                    )
                )
        try:
            for restrictedPeer in restrictedPeers:
                self.__wgSetPeer(restrictedPeer["id"], restrictedPeer['allowed_ip'].replace(" ", ""),
                                 restrictedPeer['preshared_key'])
        except subprocess.CalledProcessError as e:
            current_app.logger.error(f"{self.Name}: failed to allow access: {e.output.decode(errors='replace').strip()}")
            self.__wgSave()
            self.getPeers()
            return False, "Failed to allow access of peer(s)"

        status, msg = self.__wgSave()
        if not status:
            return False, "Failed to save configuration through WireGuard"
        self.getPeers()
        return True, "Allow access successfully"

    @peersLocked
    def restrictPeers(self, listOfPublicKeys) -> tuple[bool, str]:
        numOfFailedToRestrictPeers = 0
        if not self.getStatus():
            self.toggleConfiguration()
        self.getPeers()

        removed = []
        for p in listOfPublicKeys:
            found, pf = self.searchPeer(p)
            if found and self.__wgRemovePeer(pf.id):
                removed.append(pf.id)
            else:
                numOfFailedToRestrictPeers += 1

        if removed:
            # Persist the .conf file before touching the database, otherwise getPeers()
            # could see the peer in the file without its row and re-import it as "Untitled"
            status, msg = self.__wgSave()
            if not status:
                return False, "Failed to save configuration through WireGuard"
            with self.engine.begin() as conn:
                for peerId in removed:
                    conn.execute(
                        self.peersRestrictedTable.delete().where(self.peersRestrictedTable.columns.id == peerId)
                    )
                    conn.execute(
                        self.peersRestrictedTable.insert().from_select(
                            [c.name for c in self.peersTable.columns],
                            self.peersTable.select().where(
                                self.peersTable.columns.id == peerId
                            )
                        )
                    )
                    conn.execute(
                        self.peersRestrictedTable.update().values({
                            "status": "stopped"
                        }).where(
                            self.peersRestrictedTable.columns.id == peerId
                        )
                    )
                    conn.execute(
                        self.peersTable.delete().where(
                            self.peersTable.columns.id == peerId
                        )
                    )

        self.getRestrictedPeers()
        self.getPeers()
        numOfRestrictedPeers = len(removed)
        if numOfRestrictedPeers == len(listOfPublicKeys):
            return True, f"Restricted {numOfRestrictedPeers} peer(s)"
        return False, f"Restricted {numOfRestrictedPeers} peer(s) successfully. Failed to restrict {numOfFailedToRestrictPeers} peer(s)"

    @peersLocked
    def deletePeers(self, listOfPublicKeys, AllPeerJobs: PeerJobs, AllPeerShareLinks: PeerShareLinks) -> tuple[bool, str]:
        numOfFailedToDeletePeers = 0
        numOfNotFoundPeers = 0
        if not self.getStatus():
            self.toggleConfiguration()
        self.getPeers()

        removed = []
        for p in listOfPublicKeys:
            found, pf = self.searchPeer(p)
            if not found:
                numOfNotFoundPeers += 1
                continue
            if self.__wgRemovePeer(pf.id):
                removed.append(pf)
            else:
                numOfFailedToDeletePeers += 1

        if removed:
            # Persist the .conf file before deleting rows, otherwise getPeers() could see the
            # peer in the file without its row and re-import it as "Untitled" without a key
            status, msg = self.__wgSave()
            if not status:
                return False, "Failed to save configuration through WireGuard"
            with self.engine.begin() as conn:
                for pf in removed:
                    conn.execute(
                        self.peersTable.delete().where(
                            self.peersTable.columns.id == pf.id
                        )
                    )
            for pf in removed:
                for job in pf.jobs:
                    AllPeerJobs.deleteJob(job)
                for shareLink in pf.ShareLink:
                    AllPeerShareLinks.updateLinkExpireDate(shareLink.ShareID, datetime.now())

        self.getPeers()
        numOfDeletedPeers = len(removed)
        deleted = [pf.id for pf in removed]

        if numOfDeletedPeers == 0 and numOfFailedToDeletePeers == 0:
            return False, "No peer(s) to delete found"

        if numOfDeletedPeers == len(listOfPublicKeys):
            self.DashboardWebHooks.RunWebHook("peer_deleted", {
                "configuration": self.Name,
                "peers": deleted
            })
            return True, f"Deleted {numOfDeletedPeers} peer(s)"

        if deleted:
            self.DashboardWebHooks.RunWebHook("peer_deleted", {
                "configuration": self.Name,
                "peers": deleted
            })
        return False, f"Deleted {numOfDeletedPeers} peer(s) successfully. Failed to delete {numOfFailedToDeletePeers + numOfNotFoundPeers} peer(s)"

    def __wgSave(self) -> tuple[bool, str] | tuple[bool, None]:
        try:
            command = [f"{self.Protocol}-quick", "save", self.Name]
            subprocess.check_output(command, stderr=subprocess.STDOUT)

            return True, None
        except subprocess.CalledProcessError as e:
            current_app.logger.error(f"Failed to process command:\n{str(e)}")
            return False, "Internal server error"

    def getPeersLatestHandshake(self):
        if not self.getStatus():
            self.toggleConfiguration()
        try:
            command = [self.Protocol, "show", self.Name, "latest-handshakes"]
            latestHandshake = subprocess.check_output(command, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError:
            return "stopped"
        latestHandshake = latestHandshake.decode("UTF-8").split()
        count = 0
        now = datetime.now()
        time_delta = timedelta(minutes=3)

        with self.engine.begin() as conn:
            for _ in range(int(len(latestHandshake) / 2)):
                minus = now - datetime.fromtimestamp(int(latestHandshake[count + 1]))
                if minus < time_delta:
                    status = "running"
                else:
                    status = "stopped"
                if int(latestHandshake[count + 1]) > 0:
                    conn.execute(
                        self.peersTable.update().values({
                            "latest_handshake": str(minus).split(".", maxsplit=1)[0],
                            "status": status
                        }).where(
                            self.peersTable.columns.id == latestHandshake[count]
                        )
                    )
                else:
                    conn.execute(
                        self.peersTable.update().values({
                            "latest_handshake": "No Handshake",
                            "status": status
                        }).where(
                            self.peersTable.columns.id == latestHandshake[count]
                        )
                    )
                count += 2

    def getPeersTransfer(self):
        if not self.getStatus():
            self.toggleConfiguration()
        # try:
        command = [self.Protocol, "show", self.Name, "transfer"]
        data_usage = subprocess.check_output(command, stderr=subprocess.STDOUT)

        data_usage = data_usage.decode("UTF-8").split("\n")
        
        data_usage = [p.split("\t") for p in data_usage]
        cur_i = None
        with self.engine.begin() as conn:
            for i in range(len(data_usage)):
                if len(data_usage[i]) == 3:
                    cur_i = conn.execute(
                        self.peersTable.select().where(
                            self.peersTable.c.id == data_usage[i][0]
                        )
                    ).mappings().fetchone()
                    if cur_i is not None:
                        total_sent = cur_i['total_sent']
                        total_receive = cur_i['total_receive']
                        cur_total_sent = float(data_usage[i][2]) / (1024 ** 3)
                        cur_total_receive = float(data_usage[i][1]) / (1024 ** 3)
                        cumulative_receive = cur_i['cumu_receive'] + total_receive
                        cumulative_sent = cur_i['cumu_sent'] + total_sent
                        if (total_sent * 0.999 ) <= cur_total_sent and (total_receive * 0.999) <= cur_total_receive: # An accuracy of 1K ppm is sufficient
                            total_sent = cur_total_sent
                            total_receive = cur_total_receive
                        else:
                            conn.execute(
                                self.peersTable.update().values({
                                    "cumu_receive": cumulative_receive,
                                    "cumu_sent": cumulative_sent,
                                    "cumu_data": cumulative_sent + cumulative_receive
                                }).where(
                                    self.peersTable.c.id == data_usage[i][0]
                                )
                            )

                            total_sent = 0
                            total_receive = 0
                        status, p = self.searchPeer(data_usage[i][0])
                        if status:
                            if p.total_receive != total_receive or p.total_sent != total_sent:
                                conn.execute(
                                    self.peersTable.update().values({
                                        "total_receive": total_receive,
                                        "total_sent": total_sent,
                                        "total_data": total_receive + total_sent
                                    }).where(
                                        self.peersTable.c.id == data_usage[i][0]
                                    )
                                )

            

    def getPeersEndpoint(self):
        if not self.getStatus():
            self.toggleConfiguration()
        try:
            command = [self.Protocol, "show", self.Name, "endpoints"]
            data_usage = subprocess.check_output(command, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError:
            return "stopped"

        data_usage = data_usage.decode("UTF-8").split()
        count = 0
        with self.engine.begin() as conn:
            for _ in range(int(len(data_usage) / 2)):
                conn.execute(
                    self.peersTable.update().values({
                        "endpoint": data_usage[count + 1]
                    }).where(
                        self.peersTable.c.id == data_usage[count]
                    )
                )
                count += 2

    @peersLocked
    def toggleConfiguration(self) -> tuple[bool, str] | tuple[bool, None]:
        self.getStatus()
        if self.Status:
            try:
                command = [f"{self.Protocol}-quick", "down", self.Name]
                check = subprocess.check_output(command, stderr=subprocess.STDOUT)

                self.removeAutostart()
            except subprocess.CalledProcessError as exc:
                return False, str(exc.output.strip().decode("utf-8"))
        else:
            try:
                command = [f"{self.Protocol}-quick", "up", self.Name]
                check = subprocess.check_output(command, stderr=subprocess.STDOUT)

                self.addAutostart()
            except subprocess.CalledProcessError as exc:
                return False, str(exc.output.strip().decode("utf-8"))
        self.__parseConfigurationFile()
        self.getStatus()
        return True, None

    def getPeersList(self):
        return self.Peers

    def getRestrictedPeersList(self) -> list:
        self.getRestrictedPeers()
        return self.RestrictedPeers

    def toJson(self):
        self.Status = self.getStatus()
        return {
            "Status": self.Status,
            "Name": self.Name,
            "PrivateKey": self.PrivateKey,
            "PublicKey": self.PublicKey,
            "Address": self.Address,
            "ListenPort": self.ListenPort,
            "PreUp": self.PreUp,
            "PreDown": self.PreDown,
            "PostUp": self.PostUp,
            "PostDown": self.PostDown,
            "SaveConfig": self.SaveConfig,
            "DataUsage": {
                "Total": sum(list(map(lambda x: x.cumu_data + x.total_data, self.Peers))),
                "Sent": sum(list(map(lambda x: x.cumu_sent + x.total_sent, self.Peers))),
                "Receive": sum(list(map(lambda x: x.cumu_receive + x.total_receive, self.Peers)))
            },
            "ConnectedPeers": len(list(filter(lambda x: x.status == "running", self.Peers))),
            "TotalPeers": len(self.Peers),
            "Protocol": self.Protocol,
            "Table": self.Table,
            "Info": self.configurationInfo.model_dump()
        }

    def backupConfigurationFile(self) -> tuple[bool, dict[str, str]]:
        if not os.path.exists(os.path.join(self.__getProtocolPath(), 'WGDashboard_Backup')):
            os.mkdir(os.path.join(self.__getProtocolPath(), 'WGDashboard_Backup'))
        time = datetime.now().strftime("%Y%m%d%H%M%S")
        shutil.copy(
            self.configPath,
            os.path.join(self.__getProtocolPath(), 'WGDashboard_Backup', f'{self.Name}_{time}.conf')
        )
        with open(os.path.join(self.__getProtocolPath(), 'WGDashboard_Backup', f'{self.Name}_{time}.sql'), 'w+') as f:
            for l in self.__dumpDatabase():
                f.write(l + "\n")

        return True, {
            "filename": f'{self.Name}_{time}.conf',
            "backupDate": datetime.now().strftime("%Y%m%d%H%M%S")
        }

    def getBackups(self, databaseContent: bool = False) -> list[dict[str, str]]:
        backups = []

        directory = os.path.join(self.__getProtocolPath(), 'WGDashboard_Backup')
        files = [(file, os.path.getctime(os.path.join(directory, file)))
                 for file in os.listdir(directory) if os.path.isfile(os.path.join(directory, file))]
        files.sort(key=lambda x: x[1], reverse=True)

        for f, ct in files:
            if RegexMatch(rf"^({self.Name})_(\d+)\.(conf)$", f):
                s = re.search(rf"^({self.Name})_(\d+)\.(conf)$", f)
                date = s.group(2)
                d = {
                    "filename": f,
                    "backupDate": date,
                    "content": open(os.path.join(self.__getProtocolPath(), 'WGDashboard_Backup', f), 'r').read()
                }
                if f.replace(".conf", ".sql") in list(os.listdir(directory)):
                    d['database'] = True
                    if databaseContent:
                        d['databaseContent'] = open(os.path.join(self.__getProtocolPath(), 'WGDashboard_Backup', f.replace(".conf", ".sql")), 'r').read()
                backups.append(d)

        return backups

    def restoreBackup(self, backupFileName: str) -> bool:
        backups = list(map(lambda x : x['filename'], self.getBackups()))
        if backupFileName not in backups:
            return False
        if self.Status:
            self.toggleConfiguration()
        target = os.path.join(self.__getProtocolPath(), 'WGDashboard_Backup', backupFileName)
        targetSQL = os.path.join(self.__getProtocolPath(), 'WGDashboard_Backup', backupFileName.replace(".conf", ".sql"))
        if not os.path.exists(target):
            return False
        targetContent = open(target, 'r').read()
        try:
            with open(self.configPath, 'w') as f:
                f.write(targetContent)
        except Exception as e:
            return False
        self.__parseConfigurationFile()
        self.__importDatabase(targetSQL)
        self.__initPeersList()
        return True

    def deleteBackup(self, backupFileName: str) -> bool:
        backups = list(map(lambda x : x['filename'], self.getBackups()))
        if backupFileName not in backups:
            return False
        try:
            backupPath = os.path.join(self.__getProtocolPath(), 'WGDashboard_Backup')
            for ext in ('.conf', '.sql'):
                f = os.path.join(backupPath, os.path.splitext(backupFileName)[0] + ext)
                if os.path.exists(f):
                    os.remove(f)
        except Exception as e:
            return False
        return True

    def downloadBackup(self, backupFileName: str) -> tuple[bool, str] | tuple[bool, None]:
        backup = list(filter(lambda x : x['filename'] == backupFileName, self.getBackups()))
        if len(backup) == 0:
            return False, None
        zip = f'{str(uuid.UUID(int=random.Random().getrandbits(128), version=4))}.zip'
        with ZipFile(os.path.join('download', zip), 'w') as zipF:
            zipF.write(
                os.path.join(self.__getProtocolPath(), 'WGDashboard_Backup', backup[0]['filename']),
                os.path.basename(os.path.join(self.__getProtocolPath(), 'WGDashboard_Backup', backup[0]['filename']))
            )
            if backup[0]['database']:
                zipF.write(
                    os.path.join(self.__getProtocolPath(), 'WGDashboard_Backup', backup[0]['filename'].replace('.conf', '.sql')),
                    os.path.basename(os.path.join(self.__getProtocolPath(), 'WGDashboard_Backup', backup[0]['filename'].replace('.conf', '.sql')))
                )

        return True, zip

    def updateConfigurationSettings(self, newData: dict) -> tuple[bool, str]:
        if self.Status:
            self.toggleConfiguration()
        original = []
        dataChanged = False
        with open(self.configPath, 'r') as f:
            original = [l.rstrip("\n") for l in f.readlines()]
            allowEdit = ["Address", "PreUp", "PostUp", "PreDown", "PostDown", "ListenPort", "Table"]
            awgKeys = []
            if self.Protocol == 'awg':
                awgKeys = ["Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "I5", "HeaderProtectionKey", "ContentPaddingAddition", "RekeyAfterTime", "RekeyTimeout", "RejectAfterTime", "KeepaliveTimeout", "MaxHandshakeAttempts", "RandomTrailers", "DisableCookies", "J1", "J2", "J3", "Itime"]
                allowEdit += awgKeys
            start = original.index("[Interface]")
            try:
                end = original.index("[Peer]")
            except ValueError as e:
                end = len(original)
            new = ["[Interface]"]
            peerFound = False
            for line in range(start, end):
                split = re.split(r'\s*=\s*', original[line], 1)
                if len(split) == 2:
                    if split[0] not in allowEdit:
                        new.append(original[line])
            for key in allowEdit:
                val = str(newData.get(key, "")).strip()
                if key in awgKeys and val == "":
                    continue
                new.insert(1, f"{key} = {val}")
            new.append("")
            for line in range(end, len(original)):
                new.append(original[line])
            self.backupConfigurationFile()
            with open(self.configPath, 'w') as f:
                f.write("\n".join(new))

        status, msg = self.toggleConfiguration()
        if not status:
            return False, msg
        for i in allowEdit:
            setattr(self, i, str(newData[i]))
                
        return True, ""

    def deleteConfiguration(self):
        if self.getStatus():
            self.toggleConfiguration()
        os.remove(self.configPath)
        self.__dropDatabase()
        return True

    def renameConfiguration(self, newConfigurationName) -> tuple[bool, str]:
        newConfigurationName = os.path.basename(newConfigurationName)

        if len(newConfigurationName) > 15 or not re.match(r'^[a-zA-Z0-9_=\+\.\-]{1,15}$', newConfigurationName):
            return False, "Configuration name is either too long or contains an illegal character"
        
        newConfigurationName = newConfigurationName.replace("`", "") # double check
    
        try:
            if self.getStatus():
                self.toggleConfiguration()
            self.createDatabase(newConfigurationName)
            with self.engine.begin() as conn:
                def doRenameStatement(suffix):
                    newConfig = f"{newConfigurationName}{suffix}"
                    oldConfig = f"{self.Name}{suffix}"

                    conn.execute(
                        sqlalchemy.text(
                            f'INSERT INTO `{newConfig}` SELECT * FROM `{oldConfig}`'
                        )
                    )

                doRenameStatement("")
                doRenameStatement("_restrict_access")
                doRenameStatement("_deleted")
                doRenameStatement("_transfer")
                doRenameStatement("_history_endpoint")
                conn.execute(
                    self.infoTable.update()
                    .where(self.infoTable.c.ID == self.Name)
                    .values(ID=newConfigurationName)
                )

            self.AllPeerJobs.updateJobConfigurationName(self.Name, newConfigurationName)
            shutil.copy(
                self.configPath,
                os.path.join(self.__getProtocolPath(), f'{newConfigurationName}.conf')
            )
            self.deleteConfiguration()
        except Exception as e:
            current_app.logger.error(f"Failed to rename configuration.\nNew Configuration Name: {newConfigurationName}\nError: {str(e)}")
            return False, "Internal server error"
        return True, None

    def getNumberOfAvailableIP(self):
        if len(self.Address) < 0:
            return False, None
        existedAddress = set()
        availableAddress = {}
        for p in self.Peers + self.getRestrictedPeersList():
            peerAllowedIP = p.allowed_ip.split(',')
            for pip in peerAllowedIP:
                ppip = pip.strip().split('/')
                if len(ppip) == 2:
                    try:
                        check = ipaddress.ip_network(ppip[0])
                        existedAddress.add(check)
                    except Exception as e:
                        current_app.logger.exception(f"{self.Name} peer {p.id} have invalid ip")
        configurationAddresses = self.Address.split(',')
        for ca in configurationAddresses:
            ca = ca.strip()
            caSplit = ca.split('/')
            try:
                if len(caSplit) == 2:
                    network = ipaddress.ip_network(ca, False)
                    existedAddress.add(ipaddress.ip_network(caSplit[0]))
                    availableAddress[ca] = network.num_addresses
                    for p in existedAddress:
                        if p.version == network.version and p.subnet_of(network):
                            availableAddress[ca] -= 1
            except Exception as e:
                current_app.logger.exception(f"Error: Failed to parse IP address {ca} from {self.Name}")
        return True, availableAddress

    def getAvailableIP(self, threshold = 255):
        if len(self.Address) < 0:
            return False, None
        existedAddress = set()
        availableAddress = {}
        for p in self.Peers + self.getRestrictedPeersList():
            peerAllowedIP = p.allowed_ip.split(',')
            for pip in peerAllowedIP:
                ppip = pip.strip().split('/')
                if len(ppip) == 2:
                    try:
                        check = ipaddress.ip_network(ppip[0])
                        existedAddress.add(check.compressed)
                    except Exception as e:
                        current_app.logger.exception(f"{self.Name} peer {p.id} have invalid ip")
        configurationAddresses = self.Address.split(',')
        for ca in configurationAddresses:
            ca = ca.strip()
            caSplit = ca.split('/')
            try:
                if len(caSplit) == 2:
                    network = ipaddress.ip_network(ca, False)
                    existedAddress.add(ipaddress.ip_network(caSplit[0]).compressed)
                    if threshold == -1:
                        availableAddress[ca] = filter(lambda ip : ip not in existedAddress,
                                                      map(lambda iph : ipaddress.ip_network(iph).compressed, network.hosts()))
                    else:
                        availableAddress[ca] = list(islice(filter(lambda ip : ip not in existedAddress,
                                                                  map(lambda iph : ipaddress.ip_network(iph).compressed, network.hosts())), threshold))
            except Exception as e:
                current_app.logger.exception(f"Failed to parse IP address {ca} from {self.Name}")
        return True, availableAddress

    def getRealtimeTrafficUsage(self):
        stats = psutil.net_io_counters(pernic=True, nowrap=True)
        if self.Name in stats.keys():
            stat = stats[self.Name]
            recv1 = stat.bytes_recv
            sent1 = stat.bytes_sent
            time.sleep(1)
            stats = psutil.net_io_counters(pernic=True, nowrap=True)
            if self.Name in stats.keys():
                stat = stats[self.Name]
                recv2 = stat.bytes_recv
                sent2 = stat.bytes_sent
                net_in = round((recv2 - recv1) / 1024 / 1024, 3)
                net_out = round((sent2 - sent1) / 1024 / 1024, 3)
                return {
                    "sent": net_out,
                    "recv": net_in
                }
            else:
                return { "sent": 0, "recv": 0 }
        else:
            return { "sent": 0, "recv": 0 }
    
    '''
    Manager WireGuard Configuration Information
    '''
    
    def readConfigurationInfo(self):
        with self.engine.connect() as conn:
            result = conn.execute(
                self.infoTable.select().where(
                    self.infoTable.c.ID == self.Name
                )
            ).mappings().fetchone()
        return result
    
    def initConfigurationInfo(self):
        with self.engine.begin() as conn:
            conn.execute(
                self.infoTable.insert().values(
                    {
                        "ID": self.Name,
                        "Info": self.configurationInfo.model_dump_json()
                    }
                )
            )
    
    def storeConfigurationInfo(self):
        try:
            with self.engine.begin() as conn:
                conn.execute(
                    self.infoTable.update().values(
                        {
                            "Info": self.configurationInfo.model_dump_json()
                        }
                    ).where(
                        self.infoTable.c.ID == self.Name
                    )
                )
        except Exception as e:
            return False
        
    def updateConfigurationInfo(self, key: str, value: str | dict[str, str] | dict[str, dict] | bool) -> tuple[bool, Any, str] | tuple[
        bool, str, None] | tuple[bool, None, None]:
        if key == "Description":
            self.configurationInfo.Description = value
        elif key == "OverridePeerSettings":
            for (key, val) in value.items():
                try:
                    status, msg = self.__validateOverridePeerSettings(key, RenderSandboxedTemplate(val, configuration=self.toJson()))
                    if not status:
                        return False, msg, key
                except Exception as e:
                    return False, str(e), None
            self.configurationInfo.OverridePeerSettings = (
                self.configurationInfo.OverridePeerSettings.model_validate(value))
        elif key == "PeerGroups":
            peerGroups = {}
            for name, data in value.items():
                peerGroups[name] = PeerGroupsClass(**data)
            self.configurationInfo.PeerGroups = peerGroups
        elif key == "PeerTrafficTracking":
            self.configurationInfo.PeerTrafficTracking = value
        elif key == "PeerHistoricalEndpointTracking":
            self.configurationInfo.PeerHistoricalEndpointTracking = value
        else: 
            return False, "Key does not exist", None
        self.storeConfigurationInfo()
        return True, None, None
    
    def __validateOverridePeerSettings(self, key: str, value: str | int) -> tuple[bool, None] | tuple[bool, str]:
        status = True
        msg = None
        if key == "DNS" and value:
            status, msg = ValidateDNSAddress(value)
        elif key == "EndpointAllowedIPs" and value:
            status, msg = ValidateEndpointAllowedIPs(value)
        elif key == "ListenPort" and value:
            if not value.isnumeric() or not (1 <= int(value) <= 65535):
                status = False
                msg = "Listen Port must be >= 1 and <= 65535"        
        return status, msg
        
    def getTransferTableSize(self):
        with self.engine.connect() as db:
            row_count = db.execute(
                sqlalchemy.select(sqlalchemy.func.count()).select_from(self.peersTransferTable)
            ).scalar()
            return int(row_count)

    def getHistoricalEndpointTableSize(self):
        with self.engine.connect() as db:
            row_count = db.execute(
                sqlalchemy.select(sqlalchemy.func.count()).select_from(self.peersHistoryEndpointTable)
            ).scalar()
            return int(row_count)
        
    def downloadTransferTable(self):
        with self.engine.connect() as db:
            data = db.execute(
                self.peersTransferTable.select()
            ).mappings().fetchall()
            return data

    def downloadHistoricalEndpointTable(self):
        with self.engine.connect() as db:
            data = db.execute(
                self.peersHistoryEndpointTable.select()
            ).mappings().fetchall()
            return data
    
    def deleteTransferTable(self):
        try:
            with self.engine.begin() as db:
                db.execute(
                    self.peersTransferTable.delete()
            )
            with self.engine.connect() as conn:
                if conn.dialect.name == 'sqlite':
                    print("[WGDashboard] SQLite Vacuuming Database")
                    conn.execute(sqlalchemy.text('VACUUM;'))
        except Exception as e:
            return False
        return True

    def deleteHistoryEndpointTable(self):
        try:
            with self.engine.begin() as db:
                db.execute(
                    self.peersHistoryEndpointTable.delete()
                )
            with self.engine.connect() as conn:
                if conn.dialect.name == 'sqlite':
                    print("[WGDashboard] SQLite Vacuuming Database")
                    conn.execute(sqlalchemy.text('VACUUM;'))
        except Exception as e:
            return False
        return True
