TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += main.cpp
LIBS += -lpthread -lSDL -lSDL_ttf
QMAKE_CXXFLAGS = -std=c++17 -O3 -march=native
