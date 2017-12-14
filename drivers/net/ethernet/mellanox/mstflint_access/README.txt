MELLANOX TECHNOLOGIES LTD.


*******************************
MSTFLINT DRIVER FOR SECURE BOOT
*******************************

This kernel was developed to enable mstflint to work under secure boot enabled systems.

To work with this driver perform the following operations:

1. Run make
2. Using signtool, sign the generated mstflint_driver.ko (the key must be trusted by the system)
3. Load the driver:
    > insmod ./mstflint_access.ko
4. Run your tools with the DBDF device name format:
    > mstflint -d 05:00.0 q
    > mstmcra 05:00.0 0xf0014

*Limitation - mstflint driver supports only ConnectX-3/ConnectX-3Pro devices.


**Note - a spec file for generating source RPM from the sources will be added at a later stage
