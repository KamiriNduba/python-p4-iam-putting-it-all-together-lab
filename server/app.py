#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError
from config import app, db, api
from models import User, Recipe

# Function to check if the user is logged in before each request
@app.before_request
def check_if_logged_in():
    # List of endpoints that can be accessed without authentication
    open_access_list = [
        'signup',
        'login',
        'check_session'
    ]
    # Check if the requested endpoint requires authentication and if the user is logged in
    if (request.endpoint) not in open_access_list and (not session.get('user_id')):
        return {'error': '401 Unauthorized'}, 401

# Resource for user signup
class Signup(Resource):
    def post(self):
        request_json = request.get_json()
        username = request_json.get('username')
        password = request_json.get('password')
        image_url = request_json.get('image_url')
        bio = request_json.get('bio')
        # Create a new user instance
        user = User(
            username=username,
            image_url=image_url,
            bio=bio
        )
        # Set password hash using setter method
        user.password_hash = password
        try:
            # Add user to database
            db.session.add(user)
            db.session.commit()
            # Set user_id in session
            session['user_id'] = user.id
            return user.to_dict(), 201
        except IntegrityError:
            return {'error': '422 Unprocessable Entity'}, 422

# Resource to check user session
class CheckSession(Resource):
    def get(self):
        user_id = session['user_id']
        if user_id:
            # Query user from database
            user = User.query.filter(User.id == user_id).first()
            return user.to_dict(), 200
        return {}, 401

# Resource for user login
class Login(Resource):
    def post(self):
        request_json = request.get_json()
        username = request_json.get('username')
        password = request_json.get('password')
        # Query user from database by username
        user = User.query.filter(User.username == username).first()
        if user:
            # Authenticate user
            if user.authenticate(password):
                # Set user_id in session
                session['user_id'] = user.id
                return user.to_dict(), 200
        return {'error': '401 Unauthorized'}, 401

# Resource for user logout
class Logout(Resource):
    def delete(self):
        # Clear user_id from session
        session['user_id'] = None
        return {}, 204

# Resource for recipe index
class RecipeIndex(Resource):
    def get(self):
        # Query user's recipes from database
        user = User.query.filter(User.id == session['user_id']).first()
        return [recipe.to_dict() for recipe in user.recipes], 200

    def post(self):
        request_json = request.get_json()
        title = request_json['title']
        instructions = request_json['instructions']
        minutes_to_complete = request_json['minutes_to_complete']
        try:
            # Create a new recipe instance
            recipe = Recipe(
                title=title,
                instructions=instructions,
                minutes_to_complete=minutes_to_complete,
                user_id=session['user_id'],
            )
            # Add recipe to database
            db.session.add(recipe)
            db.session.commit()
            return recipe.to_dict(), 201
        except IntegrityError:
            return {'error': '422 Unprocessable Entity'}, 422

# Add resources to API endpoints
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')

# Run the application
if __name__ == '__main__':
    app.run(port=5555, debug=True)
