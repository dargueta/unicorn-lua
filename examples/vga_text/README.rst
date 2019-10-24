Basic Text Mode VGA
===================

This example shows how to hook writes to a section of RAM to simulate a basic
VGA controller. The implementation here will only support text mode 3, the
default mode IBM-compatible computers boot in.

**Note:** This requires the `lcurses`_ rock to be installed.

.. _lcurses: https://luarocks.org/modules/jjandresson/lcurses
