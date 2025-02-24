#!/bin/bash
gunicorn -k eventlet -w 1 secure_chat:app
