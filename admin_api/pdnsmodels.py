"""Models from the powerdns 'pdns' database."""
import sys
import os
from admin_api import ApiParser

from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine, Column, INTEGER, VARCHAR, SmallInteger, Text
from sqlalchemy.orm import sessionmaker

oneup = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
configfile = '%s/api.cfg' % (oneup)
config = ApiParser()
config.read(configfile)

dbuser = config.safe_get('database', 'user')
dbpass = config.safe_get('database', 'pass')
dbhost = config.safe_get('database', 'host')
dbdb = config.safe_get('database', 'database')
enginestring = 'mysql://%s:%s@%s/%s' % (dbuser, dbpass, dbhost, dbdb)

# pylint: disable=invalid-name
Base = declarative_base()
engine = create_engine(enginestring)
Session = sessionmaker(bind=engine)
# create a Session
session = Session()


class Domains(Base):
    """Model for the domains table."""

    __tablename__ = 'domains'
    id = Column(INTEGER(), primary_key=True, nullable=False)
    name = Column(VARCHAR(length=255))
    master = Column(VARCHAR(length=128))
    last_check = Column(INTEGER())
    type = Column(VARCHAR(length=6))
    notified_serial = Column(INTEGER())
    account = Column(VARCHAR(length=40))

    def __repr__(self):
        """Represent an instance of the class."""
        return '%s %s %s' % (self.id, self.type, self.name)

    def duplicate(self):
        """Duplicate for copy."""
        arguments = dict()
        for name, column in self.__mapper__.columns.items():
            if not (column.primary_key or column.unique):
                arguments[name] = getattr(self, name)
        return self.__class__(**arguments)


class Records(Base):
    """Model for the records database table."""

    __tablename__ = 'records'
    id = Column(INTEGER(), primary_key=True, nullable=False)
    domain_id = Column(INTEGER())
    name = Column(VARCHAR(length=255))
    type = Column(VARCHAR(length=10))
    content = Column(VARCHAR(length=64000))
    ttl = Column(INTEGER())
    prio = Column(INTEGER())
    change_date = Column(INTEGER())
    disabled = Column(SmallInteger())
    ordername = Column(VARCHAR(length=255))
    auth = Column(SmallInteger())

    def __repr__(self):
        """Represent an instance of the class."""
        return '%s %s %s %s %s' % (self.id, self.domain_id, self.type, self.name, self.content)

    def duplicate(self):
        """Duplicate for copy."""
        arguments = dict()
        for name, column in self.__mapper__.columns.items():
            if not (column.primary_key or column.unique):
                arguments[name] = getattr(self, name)
        return self.__class__(**arguments)


class Domainmetadata(Base):
    """Model for the Domain meta data."""

    __tablename__ = 'domainmetadata'
    id = Column(INTEGER(), primary_key=True, nullable=False)
    domain_id = Column(INTEGER())
    kind = Column(VARCHAR(length=32))
    content = Column(Text())

    def __init__(self, domain_id=None, kind=None, content=None):
        """Initialize properties (sql table columns)"""
        self.domain_id = domain_id
        self.kind = kind
        self.content = content


def domqry(name=None, dofirst=False):
    """get a model for a domain."""
    qry = session.query(Domains)
    if name:
        qry = qry.filter(Domains.name == name)
    if dofirst:
        qry = qry.first()
    return qry


# pylint: disable=R0913
def record_query(domid, type_=None, namelike=None, doall=False, dofirst=False, nottype=None):
    """Build query on records table."""
    nsq = session.query(Records)\
                 .filter(Records.domain_id == domid)
    if type_:
        nsq = nsq.filter(Records.type == type_)
    if nottype:
        nsq = nsq.filter(Records.type != nottype)
    if namelike:
        nsq = nsq.filter(Records.name.like("%%.%s" % (newdom.name)))
    if dofirst:
        nsq = nsq.first()
    elif doall:
        nsq = nsq.all()
    return nsq


def dupnsrecs(qry, newdom):
    """Duplicate the NS records of pop to new domain."""
    for nsrec in qry:
        print("duplicating NS record %s for %s" % (nsrec, newdom.id))
        newnsrec = nsrec.duplicate()
        newnsrec.domain_id = newdom.id
        newnsrec.name = newdom.name
        session.add(newnsrec)
    session.commit()


def dupsoarec(mdl, newdomid, newdomain_name):
    """Duplicate the SOA record from pop to new domain."""
    print("duplicating %s for %s, with name %s" % (mdl, newdomid, newdomain_name))
    newsoarec = mdl.duplicate()
    newsoarec.domain_id = newdomid
    newsoarec.name = newdomain_name
    print("newsoarec content %s" % (newsoarec.content))
    print(newsoarec)
    session.add(newsoarec)
    session.commit()
