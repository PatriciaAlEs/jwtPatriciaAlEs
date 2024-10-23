"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
from flask import Flask, request, jsonify, url_for, Blueprint
from api.models import db, User
from api.utils import generate_sitemap, APIException
from flask_cors import CORS
from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required

api = Blueprint('api', __name__)

# Allow CORS requests to this API
CORS(api)


# INICIO DE SESION 

@api.route("/login", methods=["POST"])
def login():
    request_body = request.get_json()
    email = request_body.get("email")
    password = request_body.get("password")
    
    user = User.query.filter_by(email=email).first()

    if user is None:
        return jsonify({"msg":"QUE NO LO ENCUENTRO, JOPETAS"}), 401
    print(user)
    print(user.password)
    if user.password != password:
        return jsonify({"msg":"NO ESTá BIEN ESE PASSWORD"}), 401

    # Si todo es correcto, crea el token de acceso
    access_token = create_access_token(identity=user.email)
    return jsonify(access_token=access_token)

# REGISTROOOO

@api.route("/signup", methods=["POST"])
def signup():
    request_body = request.get_json()
    email = request_body.get("email")
    password = request_body.get("password")

    if not email or not password:
        return jsonify({"msg": "All fields are required"}), 400

    # Verificar si el usuario ya existe
    user = User.query.filter_by(email=email).first()
    if user:
        return jsonify({"msg": "User already exists"}), 400

    new_user = User(email=email, password=password)

    db.session.add(new_user)
    db.session.commit()

    return jsonify({"msg": "User created successfully"}), 201



@api.route("/protected", methods=["GET"])
@jwt_required()
def protected():
    # Access the identity of the current user with get_jwt_identity
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200



@api.route('/hello', methods=['POST', 'GET'])
def handle_hello():

    response_body = {
        "message": "Hello! I'm a message that came from the backend, check the network tab on the google inspector and you will see the GET request"
    }

    return jsonify(response_body), 200
