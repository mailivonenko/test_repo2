from flask import Flask, redirect, url_for, session, request, jsonify, render_template_string, render_template
from flask_oauthlib.client import OAuth
from github import Github
from github import GithubException
import base64
import os

app = Flask(__name__)
app.secret_key = os.environ['SESSION_SECRET_KEY']  # necessary for session


# Read secret keys from env vars
GITHUB_CLIENT_ID = os.environ['GITHUB_CLIENT_ID']
GITHUB_CLIENT_SECRET = os.environ['GITHUB_CLIENT_SECRET']

oauth = OAuth(app)
github = oauth.remote_app(
    'github',
    #consumer_key='4607fa343e059f0dd456',
    #consumer_secret='ae78827b22cec87b0f1a969fde61c25114ae4818',
    consumer_key=GITHUB_CLIENT_ID,
    consumer_secret=GITHUB_CLIENT_SECRET,
    request_token_params={'scope': "user,repo"},
    base_url='https://api.github.com/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://github.com/login/oauth/access_token',
    authorize_url='https://github.com/login/oauth/authorize'
)

# List of files to replicate
FILES = [
'app.py',
'README.md',
'templates/index.html'
]

def touch_file(file_path, repo, created):
    with open(file_path) as f:
        filecontent = f.read()
    
    current_dir_files = {}
    
    if not created:
        try:
            # get repo content from root directory
            current_dir_contents = repo.get_dir_contents(path = '')
            current_dir_files = dict((f.path, f.sha) for f in current_dir_contents)
        except GithubException as e:
            #output: This repository is empty.
            print(e.args[1]['message']) 
    
    git_file_path = '/' + file_path
    
    if file_path in current_dir_files.keys():
        cur_sha = current_dir_files[file_path]
        git_msg= 'updated {}'.format(file_path)
        repo.update_file(path = git_file_path, message = git_msg, content = filecontent, sha = cur_sha)
    else:
        git_msg= 'added {}'.format(file_path)
        repo.create_file(path = git_file_path, message = git_msg, content = filecontent)



@app.route('/')
def index():
    if ('github_token' in session) & ('username' in session):
        return render_template("index.html", username=session['username'])
    else:
        return redirect(url_for('login'))


@app.route('/login')
def login():
    return github.authorize(callback=url_for('authorized', _external=True))


@app.route('/logout')
def logout():
    session.pop('github_token', None)
    session.pop('username', None)
    session.clear()
    return redirect(url_for('index'))


@app.route('/login/authorized')
def authorized():
    resp = github.authorized_response()
    if resp is None or resp.get('access_token') is None:
        return 'Access denied: reason=%s error=%s resp=%s' % (
            request.args['error'],
            request.args['error_description'],
            resp
        )
    session['github_token'] = (resp['access_token'], '')
    me = github.get('user')
    session['username'] = me.data['login']
    
    return redirect(url_for('index'))

@app.route('/replicate')
def replicate():
    
    new_repo_name = 'test_repo2'
    g1 = Github(session['github_token'][0])
    user = g1.get_user()
    created = False
    
    #Check if repo name already exists
    current_repo_names = [repo.name for repo in user.get_repos()]
    if new_repo_name in current_repo_names:
        repo = user.get_repo(new_repo_name)
        t = 'Repository {0} Already exists'.format(new_repo_name)
    else:
        repo = user.create_repo(new_repo_name)
        created = True
        t = 'Repository {0} has been created'.format(new_repo_name)
    
    for file in FILES:
        touch_file(file, repo, created)

    return render_template_string(t)

@github.tokengetter
def get_github_oauth_token():
    return session.get('github_token')


if __name__ == '__main__':
    app.run()