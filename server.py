from flask import Flask, render_template, request, redirect, jsonify, url_for, flash
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, User, Playlist, Song
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

import inspect


app = Flask(__name__)


APPLICATION_NAME = "Music Playlist"


CLIENT_ID = json.loads(
    open('client_secret.json', 'r').read())['web']['client_id']

# Connect to Database and create database session
engine = create_engine('sqlite:///musicplaylist.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

# User Helper Functions


def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except BaseException:
        return None


def findIndex(query, pid):
    if query:
        for idx, val in enumerate(query):
            print(idx, val.id, pid)
            if pid == val.id:
                return idx
    else:
        return None


# JSON APIs to view playlist Information
@app.route('/playlist/<int:playlist_id>/JSON')
def playlistJSON(playlist_id):
    playlist = session.query(Playlist).filter_by(id=playlist_id).one()
    songs = session.query(Song).filter_by(
        playlist_id=playlist_id).all()
    return jsonify(playlist=[i.serialize for i in songs])


@app.route('/playlist/<int:playlist_id>/<int:song_id>/JSON')
def songJSON(playlist_id, song_id):
    song = session.query(Song).filter_by(id=song_id).one()
    return jsonify(song=song.serialize)


@app.route('/playlist/JSON')
def playlistsJSON():
    playlists = session.query(Playlist).all()
    return jsonify(playlists=[r.serialize for r in playlists])


@app.route('/playlist/<int:playlist_id>/edit/', methods=['GET', 'POST'])
def editPlaylist(playlist_id):
    editedPlaylist = session.query(
        Playlist).filter_by(id=playlist_id).one()
    if 'username' not in login_session:
        return redirect('/login')
    if editedPlaylist.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized to edit this playlist. Please create your own playlist in order to edit.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        if request.form['name']:
            editedPlaylist.name = request.form['name']
            flash('playlist Successfully Edited %s' % editedPlaylist.name)
        return redirect(url_for('showSongs', playlist_id=playlist_id))
    else:
        return render_template('editPlaylist.html', playlist=editedPlaylist)


# Delete a playlist
@app.route('/playlist/<int:playlist_id>/delete/', methods=['GET', 'POST'])
def deletePlaylist(playlist_id):
    playlistToDelete = session.query(
        Playlist).filter_by(id=playlist_id).one()
    if 'username' not in login_session:
        return redirect('/login')
    if playlistToDelete.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized to delete this playlist. Please create your own playlist in order to delete.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        session.delete(playlistToDelete)
        flash('%s Successfully Deleted' % playlistToDelete.name)
        session.commit()
        return redirect(url_for('showPlaylist', playlist_id=playlist_id))
    else:
        return render_template(
            'deletePlaylist.html',
            playlist=playlistToDelete)


# Create a new item
@app.route('/playlist/<int:playlist_id>/new/', methods=['GET', 'POST'])
def newSong(playlist_id):
    if 'username' not in login_session:
        return redirect('/login')
    playlist = session.query(Playlist).filter_by(id=playlist_id).one()
    if login_session['user_id'] != playlist.user_id:
        return "<script>function myFunction() {alert('You are not authorized to add items to this playlist. Please create your own playlist in order to add items.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        newItem = Song(
            name=request.form['name'],
            artist=request.form['artist'],
            album=request.form['album'],
            playlist_id=playlist_id,
            user_id=playlist.user_id)
        session.add(newItem)
        session.commit()
        flash(
            'New %s Song Successfully Added to the Playlist' %
            (newItem.name))
        return redirect(url_for('showSongs', playlist_id=playlist_id))
    else:
        return render_template('newsong.html', playlist_id=playlist_id)


@app.route('/playlist/<int:playlist_id>/<int:song_id>')
def showSong(playlist_id, song_id):
    song = session.query(Song).filter_by(id=song_id).one()
    return render_template('song.html', song=song, playlist_id=playlist_id)


@app.route('/playlist/<int:playlist_id>/')
def showSongs(playlist_id):
    playlists = session.query(Playlist).order_by(asc(Playlist.name))
    if playlists:
        pid = findIndex(playlists, playlist_id)
    # return render_template('playlists.html', playlists=playlists)
    playlist = playlists[pid]
    creator = getUserInfo(playlist.user_id)
    songs = session.query(Song).filter_by(
        playlist_id=playlist_id).all()
    if 'username' not in login_session or creator.id != login_session['user_id']:
        return render_template(
            'playlist.html',
            songs=songs,
            playlist=playlist,
            creator=creator,
            playlists=playlists)
    else:
        return render_template(
            'playlist.html',
            songs=songs,
            playlist=playlist,
            creator=creator,
            playlists=playlists)


@app.route(
    '/playlist/<int:playlist_id>/<int:song_id>/edit',
    methods=[
        'GET',
        'POST'])
def editSong(playlist_id, song_id):
    if 'username' not in login_session:
        return redirect('/login')
    playlist = session.query(Playlist).filter_by(id=playlist_id).one()
    if login_session['user_id'] != playlist.user_id:
        return "<script>function myFunction() {alert('You are not authorized to edit menu items to this playlist. Please create your own playlist in order to edit items.');}</script><body onload='myFunction()''>"
    song = session.query(Song).filter_by(id=song_id).one()
    playlist = session.query(Playlist).filter_by(id=playlist_id).one()
    if request.method == 'POST':
        if request.form['name']:
            song.name = request.form['name']
        if request.form['artist']:
            song.artist = request.form['artist']
        if request.form['album']:
            song.album = request.form['album']
        session.add(song)
        session.commit()
        flash('Song Successfully Edited')
        return redirect(
            url_for(
                'showSong',
                playlist_id=playlist_id,
                song_id=song_id))
    else:
        return render_template(
            'editsong.html',
            playlist_id=playlist_id,
            song_id=song_id,
            song=song)


@app.route(
    '/playlist/<int:playlist_id>/<int:song_id>/delete',
    methods=[
        'GET',
        'POST'])
def deleteSong(playlist_id, song_id):
    if 'username' not in login_session:
        return redirect('/login')
    playlist = session.query(Playlist).filter_by(id=playlist_id).one()
    if login_session['user_id'] != playlist.user_id:
        return "<script>function myFunction() {alert('You are not authorized to edit menu items to this playlist. Please create your own playlist in order to edit items.');}</script><body onload='myFunction()''>"
    song = session.query(Song).filter_by(id=song_id).one()
    playlist = session.query(Playlist).filter_by(id=playlist_id).one()
    if request.method == 'POST':
        session.delete(song)
        session.commit()
        flash('Menu Item Successfully Deleted')
        return redirect(
            url_for(
                'showSongs',
                playlist_id=playlist_id,
                song_id=song_id))
    else:
        return render_template('deleteSong.html', song=song)


@app.route('/')
@app.route('/playlist')
def showPlaylist():
    playlists = session.query(Playlist).order_by(asc(Playlist.name))
    return render_template('playlists.html', playlists=playlists)

# Create anti-forgery state token


@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secret.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output


@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    credentials = login_session.get('access_token')
    print credentials
    access_token = login_session['access_token']
    print 'In gdisconnect access token is %s', access_token
    if credentials is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = credentials
    print '1'
    # Execute HTTP GET request to revoke current token. (# or access_token)
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % credentials
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] != '200':
        # For whatever reason, the given token was invalid.
        response = make_response(
            json.dumps('Failed to revoke token for given user.'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/newPlaylist', methods=['GET', 'POST'])
def newPlaylist():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newPlaylist = Playlist(
            name=request.form['name'], user_id=login_session['user_id'])
        session.add(newPlaylist)
        flash('New Playlist %s Successfully Created' % newPlaylist.name)
        session.commit()
        return redirect(url_for('showPlaylist'))
    else:
        return render_template('newPlaylist.html')


@app.route('/clearSession')
def clearSession():
    login_session.clear()
    return "Session cleared"


@app.route('/whoami')
def whoami():
    return str(login_session['user_id'])


@app.route('/logout')
def logout():
    if 'username' in login_session:
        gdisconnect()
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        flash("You have successfully been logged out.")
        return redirect(url_for('showPlaylist'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showPlaylist'))


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=2000)
