import os
import email
from unicodedata import category
from xmlrpc.client import DateTime
from datetime import datetime, timedelta
from bidder_package.initialization import *
from bidder_package.models import *
from flask_restful import Resource, abort, fields, marshal_with, reqparse
from flask import request, make_response, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from functools import wraps
import json
from dateutil import parser
import urllib.request
from werkzeug.utils import secure_filename

ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):

        token = None

        if 'x-access-tokens' in request.headers:
            token = request.headers['x-access-tokens']

        if not token:
            # return jsonify({'message': 'a valid token is missing'})
            abort(404, message="valid token is missing")

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
        except:
            # return jsonify({'message': 'token is invalid'})
            abort(404, message="token is invalid")

            return f(*args, **kwargs)
    return decorator


category_post_args = reqparse.RequestParser()
category_post_args.add_argument(
    "name", type=str, help="Name of the category is required", required=True)

product_post_args = reqparse.RequestParser()
product_post_args.add_argument(
    "productName", type=str, help="Product name is required", required=True)
product_post_args.add_argument(
    "productDescription", type=str, help="Product Description is required", required=True)
product_post_args.add_argument(
    "productPrice", type=str, help="Product Price is required", required=True)
product_post_args.add_argument(
    "bidStartTime", type=str, help="Product bid start date")
product_post_args.add_argument(
    "bidEndTime", type=str, help="Product bid end date")
product_post_args.add_argument(
    "category_id", type=int, help="Category Id is required", required=True)
product_post_args.add_argument(
    "user_id", type=int, help="User Id is required", required=True)

user_post_args = reqparse.RequestParser()


user_post_args.add_argument(
    "firstname", type=str, help="FirstName is required", required=True)
user_post_args.add_argument(
    "lastname", type=str, help="LastName is required", required=True)
user_post_args.add_argument(
    "email", type=str, help="Email is required", required=True)
user_post_args.add_argument(
    "password", type=str, help="password is required", required=True)
user_post_args.add_argument(
    "phone", type=str, help="Phone is required", required=True)

user_fields = {
    'id': fields.Integer,
    'firstname': fields.String,
    'lastname': fields.String,
    'email': fields.String,
    'phone': fields.String,
}


product_fields = {
    'id': fields.Integer,
    'productName': fields.String,
    'productDescription': fields.String,
    'productPrice': fields.Integer,
    'bidStartTime': fields.String,
    'bidEndTime': fields.String,
    'dateCreated': fields.DateTime,
    'category': fields.Nested({
        'id': fields.Integer,
        'name': fields.String,
    }),
    'usersbidded': fields.List(fields.Nested(user_fields)),
}

category_resource = {
    'id': fields.Integer,
    'name': fields.String,
    'products': fields.List(fields.Nested(product_fields)),
}


@app.route('/upload', methods=['POST'])
def upload_file():
    data = request.get_json()
    data1 = request.form
    data2 = request.data
    # return jsonify({
    #     'data': data,
    #     'data1': data1,
    #     'data2': str(data2)
    # })
    # check if the post request has the file part
    if 'files[]' not in request.files:
        resp = jsonify({'message': 'No file part in the request'})
        resp.status_code = 400
        return resp

    files = request.files.getlist('files[]')

    errors = {}
    success = False

    for file in files:
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            success = True
        else:
            errors[file.filename] = 'File type is not allowed'

    if success and errors:
        errors['message'] = 'File(s) successfully uploaded'
        resp = jsonify(errors)
        resp.status_code = 500
        return resp
    if success:
        resp = jsonify({'message': 'Files successfully uploaded'})
        resp.status_code = 201
        return resp
    else:
        resp = jsonify(errors)
        resp.status_code = 500
        return resp


class ProductList(Resource):
    method_decorators = {
        'get': [marshal_with(product_fields,)]}

    # @marshal_with(product_fields)
    def get(self):
        result = Product.query.all()
        if not result:
            abort(404, message="No products available")
        return result

    # @marshal_with(product_fields)
    def post(self):
        args = product_post_args.parse_args()
        # return jsonify({
        #     'data3': 'images' in request.files,
        #     'from_args': args,
        #     'data': request.form,
        #     'data_json': str(request.get_json())
        # })
        catergory_result = Category.query.filter_by(
            id=args['category_id']).first()
        user_result = User.query.filter_by(
            id=args['user_id']).first()

        if 'images' not in request.files:
            resp = jsonify({'message': 'No file part in the request'})
            resp.status_code = 400
            return resp

        if not catergory_result:
            abort(
                409, message=f"The category you are trying to insert the product does not exist")
        if not user_result:
            abort(
                409, message=f"The User you are trying to insert the product does not exist")

        product = Product(productName=args['productName'], productDescription=args['productDescription'], productPrice=args['productPrice'],
                          bidStartTime=args['bidStartTime'], bidEndTime=args['bidEndTime'], category=catergory_result, user=user_result)

        db.session.add(product)
        db.session.commit()

        # image upload feature
        files = request.files.getlist('images')

        errors = {}
        success = False

        for file in files:
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                image = Images(product_id=product.id, imageLink=app.config['HOSTNAME'] + os.path.join(
                    app.config['UPLOAD_FOLDER'] +'/'+ filename))
                db.session.add(image)
                db.session.commit()
                
                success = True
            else:
                errors[file.filename] = 'File type is not allowed'

        if success and errors:
            errors['message'] = 'File(s) successfully uploaded'
            resp = jsonify(errors)
            resp.status_code = 500
            return resp
        if success:
            resp = jsonify({'message': 'Files successfully uploaded'})
            resp.status_code = 201
            return resp
        else:
            resp = jsonify(errors)
            resp.status_code = 500
            return resp

        return product, 201


class CategoriesList(Resource):
    method_decorators = {'post': [marshal_with(category_resource)]}

    @marshal_with(category_resource)
    def get(self):
        result = Category.query.all()
        if not result:
            abort(404, message="No Categories available")
        return result

    def post(self):
        args = category_post_args.parse_args()
        result = Category.query.filter_by(name=args['name']).first()
        if result:
            abort(
                409, message=f"Category with the name ---{args['name']}--- already exist")
        category = Category(name=args['name'])
        db.session.add(category)
        db.session.commit()
        return category, 201


class SingleCategory(Resource):
    @marshal_with(category_resource)
    def get(self, category_id):
        result = Category.query.filter_by(id=category_id).first()
        if not result:
            abort(404, message="The categories you are requesting does not exist")
        return result


class UsersList(Resource):
    @marshal_with(user_fields)
    def get(self):
        data = request.get_json()
        result = User.query.all()
        if not result:
            abort(404, message="No Users available")
        return result

    def post(self):
        args = user_post_args.parse_args()
        result = User.query.filter_by(email=args['email']).first()
        if result:
            abort(
                409, message=f"User with the email ---{args['email']}--- already exist")
        user = User(firstname=args['firstname'], lastname=args['lastname'], email=args['email'],
                    password_hash=generate_password_hash(args['password'], method='sha256'), phone=args['phone'])
        db.session.add(user)
        db.session.commit()
        map_json = {
            'signUp': True
        }
        return jsonify(map_json)


class Login(Resource):

    def post(self):
        data1 = request.form
        data = request.data
        data = json.loads(data.decode('utf-8'))

        data2 = request.get_json()

        # if not auth or not auth.username or not auth.password:
        #     return make_response('could not verify', 401, {'WWW.Authentication': 'Basic realm: "login required"'})

        if not data2 or not data2['email'] or not data2['password']:
            abort(
                404, message=f"login required {data1} ------------ other {data['username']} --------json{data2}")
            # return {"status": "I am herererere"}

        user = User.query.filter_by(email=data2['email']).first()

        if not user:
            abort(404, message=f"invalid email or password")

        if check_password_hash(user.password_hash, data2['password']):
            token = jwt.encode({'user': user.email, 'exp': datetime.utcnow(
            ) + timedelta(minutes=30)}, app.config['SECRET_KEY'])
            map_json = {
                'token': token.decode('UTF-8'),
                'login': True,
                'user': {
                    'id': user.id,
                    'firstname': user.firstname,
                    'lastname': user.lastname,
                    'email': user.email,
                    'phone': user.phone,
                    'date_created': user.date_created
                }
            }
            return jsonify(map_json)

        abort(404, message=f"login required")

        # return make_response('could not verify', 401, {'WWW.Authentication': 'Basic realm: "login required"'})


api.add_resource(ProductList, '/products')
api.add_resource(CategoriesList, "/categories")
api.add_resource(SingleCategory, "/categories/<int:category_id>")
api.add_resource(UsersList, "/users")
api.add_resource(Login, '/login')

if __name__ == "__main__":
    app.run(debug=True)
