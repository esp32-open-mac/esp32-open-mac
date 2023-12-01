# License README

This project contains code based on reverse engineering the blobs distributed in https://github.com/espressif/esp32-wifi-lib. Espressif licenses these blobs under the Apache License 2.0 (see https://choosealicense.com/licenses/apache-2.0/)

> [The Apache 2.0 license is a] permissive license whose main conditions require preservation of copyright and license notices. Contributors provide an express grant of patent rights. Licensed works, modifications, and larger works may be distributed under different terms and without source code. (from https://choosealicense.com/licenses/apache-2.0/, under https://creativecommons.org/licenses/by/3.0/)

The main two conditions we need to adhere to are:

-  License and copyright notice: a copy of the license and copyright must be included with the licensed material: see LICENSE.esp32-wifi-lib.txt
- State changes: changes to the licensed materials must be documented; this is done below

## Changes to esp32-wifi-lib

This project attempts to be a clean, open-source rewrite of the blobs included in esp32-wifi-lib. Symbol names from the blobs might be used to be able to link to the blob (see `proprietary.h`). Functionality is reverse engineered from the blobs, but is not literally copied; reverse engineering was mainly used to figure out how the hardware works, since this is not documented in the public data sheet.

## License of the project itself

To keep things simple, this project itself is licensed under the MIT license, see LICENSE.md.
