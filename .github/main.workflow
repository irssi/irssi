# workflow "Check Irssi" {
#   on = "push"
#   resolves = [
#     "script",
#     "unit_tests",
#   ]
# }

action "install" {
  uses = "irssi-import/actions-irssi/check-irssi@master"
  args = "before_install install"
}

action "script" {
  uses = "irssi-import/actions-irssi/check-irssi@master"
  needs = ["install"]
  args = "before_script script after_script"
  env = {
    TERM = "xterm"
  }
}

action "unit_tests" {
  uses = "irssi-import/actions-irssi/check-irssi@master"
  needs = ["install"]
  args = "unit_tests after_unit_tests"
}
