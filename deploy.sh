#!/bin/bash
export GPG_TTY=$(tty)
mvn deploy -P release

