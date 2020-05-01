from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime
from sqlalchemy import DateTime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, relationship


engine = create_engine('sqlite:///DynDNS_server_DB')
Session = sessionmaker(bind=engine)
session = Session()
Base = declarative_base()




#
class DynDNS(Base):
    __tablename__ = 'DynDNS'
    dyndns_id = Column(Integer(), primary_key=True)
    USER = Column((String(63)), ForeignKey('users.username'))
    NAME = Column(String(63))
    TYPE = Column(String(16))
    CLASS = Column(String(16))
    TTL = Column(String(32))
    RDLENGTH = Column(String(16))
    ANCOUNT = Column(String(16))
    RDATA = Column(String(255))
    Time_stop = Column(String(63), default="millenium")
    created_on = Column(DateTime(), default=datetime.now)
    updated_on = Column(DateTime(), default=datetime.now, onupdate=datetime.now)
    STATUS = Column(String(63))


def __ini__(self, dyndns_id, USER, NAME, TYPE, CLASS, TTL, RDLENGTH, ANCOUNT, RDATA,\
            Time_stop, created_on, updated_on, STATUS):
        self.dyndns_id = dyndns_id
        self.USER = USER
        self.NAME = NAME
        self.TYPE = TYPE
        self.CLASS = CLASS
        self.TTL = TTL
        self.RDLENGTH = RDLENGTH
        self.ANCOUNT = ANCOUNT
        self.RDATA = RDATA
        self.Time_stop = Time_stop
        self.created_on = created_on
        self.updated_on = updated_on
        self.STATUS = STATUS


def __repr__(self):
    return "DynDNS(NAME='{self.NAME}', " \
           "USER='{self.USER}', " \
           "TYPE='{self.TYPE}', " \
           "CLASS='{self.CLASS}', " \
           "TTL='{self.TTL}', " \
           "RDLENGTH='{self.RDLENGTH}', " \
           "RDATA='{self.RDATA}', " \
           "ANCOUNT='{self.ANCOUNT}',"\
           "Time_stop='{self.Time_stop}', " \
           "created_on='{self.created_on}', " \
           "STATUS='{self.STATUS}', " \
           "updated_on='{self.updated_on}')".format(self=self)

#
class User(Base):
    __tablename__ = 'users'
    user_id = Column(Integer(), primary_key=True)
    username = Column(String(15), nullable=False, unique=True)
    password = Column(String(25), nullable=False)
    time_stop = Column(String(63), default="millenium")
    created_on = Column(DateTime(), default=datetime.now)
    updated_on = Column(DateTime(), default=datetime.now, onupdate=datetime.now)
    DynDNS = relationship("DynDNS")


def __init__(self, username, password, time_stop, created_on, updated_on):
    self.username = username
    self.password = password
    self.time_stop = time_stop
    self.created_on = created_on
    self.updated_on = updated_on


def __repr__(self):
    return "User(username='{self.username}', " \
           "time_stop='{self.time_stop}', " \
           "password='{self.password}')".format(self=self)


Base.metadata.create_all(engine)

