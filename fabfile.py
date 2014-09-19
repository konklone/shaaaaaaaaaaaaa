import time
from fabric.api import run, execute, env

environment = "production"

env.use_ssh_config = True
env.hosts = ["shaaaaa"]

branch = "master"
repo = "git@github.com:konklone/shaaaaaaaaaaaaa.git"

username = "shaaaaa"
home = "/home/%s/%s" % (username, username)
shared_path = "%s/shared" % home
versions_path = "%s/versions" % home
version_path = "%s/%s" % (versions_path, time.strftime("%Y%m%d%H%M%S"))
current_path = "%s/current" % home
logs = "/home/%s" % username

keep = 5


def checkout():
  run('git clone -q -b %s %s %s' % (branch, repo, version_path))

def dependencies():
  run('cd %s && npm install' % version_path)

# TODO: why did I do this? (cp instead of ln)
def make_current():
  # run('rm -f %s && ln -s %s %s' % (current_path, version_path, current_path))
  run('rm -rf %s && cp -r %s %s' % (current_path, version_path, current_path))

def cleanup():
  versions = run("ls -x %s" % versions_path).split()
  destroy = versions[:-keep]

  for version in destroy:
    command = "rm -rf %s/%s" % (versions_path, version)
    run(command)


## can be run on their own

def start():
  # run("cd %s && NODE_ENV=%s forever -l %s/forever.log -a start app.js -p 3000" % (current_path, environment, logs))
  run(("cd %s && " +
    "NODE_ENV=%s forever -l %s/forever.log -a start app.js 3000 && " +
    "NODE_ENV=%s forever -l %s/forever.log -a start app.js 3001") %
    (current_path, environment, logs, environment, logs)
  )

def stop():
  run("forever stop app.js")

def restart():
  run("forever restart app.js")

def deploy():
  execute(checkout)
  execute(dependencies)
  execute(make_current)
  execute(restart)
  execute(cleanup)
