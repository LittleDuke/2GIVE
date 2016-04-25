#!/bin/bash
# create multiresolution windows icon
ICON_DST=../../src/qt/res/icons/cleanwatercoin.ico

convert ../../src/qt/res/icons/cleanwatercoin-16.png ../../src/qt/res/icons/cleanwatercoin-32.png ../../src/qt/res/icons/cleanwatercoin-48.png ${ICON_DST}
