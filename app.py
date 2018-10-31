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
'templates/index.html',
'templates/test.txt'
]

def touch_file(file_path, repo):
    with open(file_path) as f:
        filecontent = f.read()
    
    git_file_path = '/' + file_path
    
    try:
        # file already exists in repo
        current_file_content = repo.get_file_contents(path = git_file_path)
        cur_sha = current_file_content.sha
        git_msg= 'updated {}'.format(file_path)
        repo.update_file(path = git_file_path, message = git_msg, content = filecontent, sha = cur_sha)
        file_action_str = 'updated'

    except GithubException as e:
        #output: File paht is not exists
        print(git_file_path, 'is new for dir')
        git_msg= 'added {}'.format(file_path)
        repo.create_file(path = git_file_path, message = git_msg, content = filecontent)
        file_action_str = 'created'
    
    return(file_action_str)


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
    
    #Check if repo name already exists
    current_repo_names = [repo.name for repo in user.get_repos()]
    if new_repo_name in current_repo_names:
        repo = user.get_repo(new_repo_name)
    else:
        repo = user.create_repo(new_repo_name)
    
    files_statuses = {}
    user_git_url = 'https://github.com/{0}/{1}'.format(session['username'], new_repo_name)
    for file in FILES:
        files_statuses[file] = touch_file(file, repo)
    
    return render_template("status.html", files_statuses=files_statuses, user_git_url = user_git_url)


@github.tokengetter
def get_github_oauth_token():
    return session.get('github_token')


if __name__ == '__main__':
    app.run()