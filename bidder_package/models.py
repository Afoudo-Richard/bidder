from enum import unique
from bidder_package.initialization import *
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

user_bid = db.Table('user_bid',
                    db.Column('id', db.Integer, primary_key=True),
                    db.Column('user_id', db.Integer, db.ForeignKey(
                        'user.id')),
                    db.Column('product_id', db.Integer,
                              db.ForeignKey('product.id')),
                    )


class User(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String(100), nullable=False)
    lastname = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(200), nullable=False, unique=True)
    password_hash = db.Column(db.String(200), nullable=False)
    phone = db.Column(db.String(200), nullable=False)
    date_created = db.Column(
        db.DateTime, nullable=False, default=datetime.utcnow)

    bids = db.relationship(
        'Product', secondary=user_bid, backref=db.backref('usersbidded', lazy=True))
    
    # products = db.relationship('Product', backref=db.backref('user', lazy=True),primaryjoin="User.id == Product.user_id")

    products = db.relationship(
        'Product', backref=db.backref('user', lazy=True))

    # @property
    # def password(self):
    #     raise AttributeError("Password is not a readable attribute")

    # @password.setter
    # def password(self, password):
    #     self.password_hash = generate_password_hash(password)

    # def verify_password(self, password):
    #     return check_password_hash(self.password_hash, password)


class Product(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    productName = db.Column(db.String(100), nullable=False)
    productDescription = db.Column(db.String(500), nullable=False)
    productPrice = db.Column(db.Integer, nullable=False)
    dateCreated = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    bidStartTime = db.Column(db.String(500), nullable=True)
    bidEndTime = db.Column(db.String(500), nullable=True)
    
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    images = db.relationship(
        'Images', backref=db.backref('product', lazy=True))

    # def __repr__(self):
    #     return '<Product %r>' % self.product_name


class Category(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    products = db.relationship(
        'Product', backref=db.backref('category', lazy=True))

    # def __repr__(self):
    #     return '<Category %r>' % self.name

class Images(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'))
    imageLink = db.Column(db.String(500), nullable=False)
    

#db.create_all()
