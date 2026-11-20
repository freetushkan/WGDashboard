"""
AmneziaWG Configuration
"""
import random, sqlalchemy, os, subprocess, re, uuid
from flask import current_app
from .PeerJobs import PeerJobs
from .AmneziaPeer import AmneziaPeer
from .PeerShareLinks import PeerShareLinks
from .Utilities import RegexMatch, CheckAddress, CheckPeerKey
from .WireguardConfiguration import WireguardConfiguration
from .DashboardWebHooks import DashboardWebHooks


class AmneziaConfiguration(WireguardConfiguration):
    def __init__(self,
                 DashboardConfig,
                 AllPeerJobs: PeerJobs,
                 AllPeerShareLinks: PeerShareLinks,
                 DashboardWebHooks: DashboardWebHooks,
                 name: str = None,
                 data: dict = None,
                 backup: dict = None,
                 startup: bool = False):
        self.Jc = 0
        self.Jmin = 0
        self.Jmax = 0
        self.S1 = 0
        self.S2 = 0
        self.S3 = 0
        self.S4 = 0
        self.H1 = 1
        self.H2 = 2
        self.H3 = 3
        self.H4 = 4
        self.I1 = ""
        self.I2 = ""
        self.I3 = ""
        self.I4 = ""
        self.I5 = ""
        self.HeaderProtectionKey = ""
        self.ContentPaddingAddition = 0
        self.RekeyAfterTime = 0
        self.RekeyTimeout = 0
        self.RejectAfterTime = 0
        self.KeepaliveTimeout = 0
        self.MaxHandshakeAttempts = 0
        self.RandomTrailers = 0
        self.DisableCookies = 0
        self.J1 = ""
        self.J2 = ""
        self.J3 = ""
        self.Itime = ""

        super().__init__(DashboardConfig, AllPeerJobs, AllPeerShareLinks, DashboardWebHooks, name, data, backup, startup, wg=False)

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
            "Info": self.configurationInfo.model_dump(),
            "DataUsage": {
                "Total": sum(list(map(lambda x: x.cumu_data + x.total_data, self.Peers))),
                "Sent": sum(list(map(lambda x: x.cumu_sent + x.total_sent, self.Peers))),
                "Receive": sum(list(map(lambda x: x.cumu_receive + x.total_receive, self.Peers)))
            },
            "ConnectedPeers": len(list(filter(lambda x: x.status == "running", self.Peers))),
            "TotalPeers": len(self.Peers),
            "Protocol": self.Protocol,
            "Table": self.Table,
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

    def _newPeer(self, tableData) -> AmneziaPeer:
        # getPeers()/addPeers()/getRestrictedPeers() are shared with WireguardConfiguration
        return AmneziaPeer(tableData, self)
