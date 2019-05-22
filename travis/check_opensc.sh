ls -lh /usr/lib/x86_64-linux-gnu/libopensc*
echo ""
echo "opensc-pkcs11.pc:"
cat /usr/lib/x86_64-linux-gnu/pkgconfig/opensc-pkcs11.pc
echo ""
echo "opensc.pc:"
cat /usr/lib/x86_64-linux-gnu/pkgconfig/opensc.pc
echo ""
diff /usr/lib/x86_64-linux-gnu/pkgconfig/opensc-pkcs11.pc /usr/lib/x86_64-linux-gnu/pkgconfig/opensc.pc
echo ""
opensc-tool -i
echo ""
