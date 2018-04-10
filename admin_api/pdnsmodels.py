"""Models from the powerdns 'pdns' database."""
import sys
import os
from admin_api import ApiParser

from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine, Column, INTEGER, VARCHAR, SmallInteger
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
