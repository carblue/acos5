#
# PKCS15 r/w profile for ACOS5 cards
#
# file.type is used differently here: The ACOS5 file type: File Descriptor Byte

cardinfo {
    label        = "ACOS5-64 Card";
    manufacturer    = "https://github.com/carblue/acos5_64";
    min-pin-length    = 8;
    # max length should be overridden in the per-card profile
    max-pin-length    = 8;
}

#
# The following controls some aspects of the PKCS15 we put onto
# the card.
#
pkcs15 {
    # Put certificates into the CDF itself?
    direct-certificates    = no;
    # Put the DF length into the ODF file?
    encode-df-length    = no;
    # Have a lastUpdate field in the EF(TokenInfo)?
    do-last-update    = no;
    # Method to calculate ID of the crypto objects
    #     native: 'E' + number_of_present_objects_of_the_same_type
    #     mozilla: SHA1(modulus) for RSA, SHA1(pub) for DSA
    #     rfc2459: SHA1(SequenceASN1 of public key components as ASN1 integers)
    # default value: 'native'
    pkcs15-id-style    = native;
}

# Default settings.
# This option block will always be processed.
option default {
    macros {
        protected    = *=$SOPIN, READ=NEVER;
        unprotected    = *=NONE;
        so-pin-flags    = local, initialized, needs-padding, soPin;
        so-min-pin-length = 8;
        so-pin-attempts    = 8;
        so-auth-id    = FF;
        so-puk-attempts    = 8;
        so-min-puk-length = 8;

        unusedspace-size = 128;
        odf-size    = 128; # 9*12
        aodf-size    = 256; # 4*52
        cdf-size    = 1530;
        cdf-trusted-size = 510;
        prkdf-size    = 768;
        pukdf-size    = 1536;
        skdf-size    = 256;
        dodf-size    = 256;
    }
}

# This option sets up the card so that a single
# user PIN protects all files
option onepin {
    macros {
        protected    = *=$PIN, READ=NEVER;
        unprotected    = *=NONE;
        so-pin-flags    = local, initialized, needs-padding;
        so-min-pin-length = 4;
        so-pin-attempts    = 3;
        so-auth-id    = 1;
        so-puk-attempts    = 7;
        so-min-puk-length = 4;
    }
}

# This option is for cards with very little memory.
# It sets the size of various PKCS15 directory files
# to 128 or 256, respectively.
option small {
    macros {
        odf-size    = 128;
        aodf-size    = 128;
        cdf-size    = 256;
        prkdf-size    = 128;
        pukdf-size    = 128;
        dodf-size    = 128;
    }
}

# This option tells pkcs15-init to use the direct option
# when storing certificates on the card (i.e. put the
# certificates into the CDF itself, rather than a
# separate file)
option direct-cert {
    pkcs15 {
        direct-certificates    = yes;
        encode-df-length    = yes;
    }
    macros {
        cdf-size    = 3192;
    }
}

# Define reasonable limits for PINs and PUK
# Note that we do not set a file path or reference
# for the user pin; that is done dynamically.
PIN user-pin {
    attempts    = 8;
    flags    = local, initialized, needs-padding;
}
PIN user-puk {
    attempts    = 8;
}
PIN so-pin {
    auth-id    = $so-auth-id;
    attempts    = $so-pin-attempts;
    min-length    = $so-min-pin-length;
    flags    = $so-pin-flags;
}
PIN so-puk {
    attempts    = $so-puk-attempts;
    min-length    = $so-min-puk-length;
}

filesystem {
    DF MF {
        path    = 3F00;
        type    = 0x3F;

        # This is the DIR file
        EF DIR {
            file-id    = 2F00;
            type    = 1;
            structure = transparent;
            size    = 128;
            ACL        = $unprotected;
        }

        # Here comes the application DF
        DF PKCS15-AppDF {
            file-id    = 4100;
            type    = 0x38;
            AID        = 41:43:4F:53:50:4B:43:53:2D:31:35:76:31:2E:30:30;
            ACL        = *=SCB1, DELETE-SELF=SCB1, LOCK=NEVER;

            EF PKCS15-ODF {
                file-id   = 5031;
                type      = 1;
                structure = transparent;
                size      = $odf-size;
                ACL       = $unprotected;
            }

            EF PKCS15-TokenInfo {
                file-id   = 5032;
                type      = 1;
                structure = transparent;
                size      = 256;
                ACL       = $unprotected;
            }

            EF PKCS15-UnusedSpace {
                file-id   = 5033;
                type      = 1;
                structure = transparent;
                size      = $unusedspace-size;
                ACL       = $unprotected;
            }

            EF PKCS15-PrKDF {
                file-id   = 4112; #4110;
                type      = 1;
                structure = transparent;
                size      = $prkdf-size;
                ACL       = $unprotected;
            }

            EF PKCS15-PuKDF {
                file-id   = 4113; #4111;
                type      = 1;
                structure = transparent;
                size      = $pukdf-size;
                ACL       = $unprotected;
            }

            EF PKCS15-SKDF {
                file-id   = 4114; #4113;
                type      = 1;
                structure = transparent;
                size      = $skdf-size;
                ACL       = $unprotected;
            }

            EF PKCS15-CDF {
                file-id   = 4115; #4114;
                type      = 1;
                structure = transparent;
                size      = $cdf-size;
                ACL       = $unprotected;
            }

            EF PKCS15-CDF-TRUSTED {
                file-id   = 4116; #4115;
                type      = 1;
                structure = transparent;
                size      = $cdf-trusted-size;
                ACL       = *=NEVER, READ=NONE, UPDATE=$PIN, DELETE=$SOPIN;
            }

            EF PKCS15-DODF {
                file-id   = 4117;
                type      = 1;
                structure = transparent;
                size      = $dodf-size;
                ACL       = $unprotected;
            }

            EF PKCS15-AODF {
                file-id   = 4111; #4118;
                type      = 1;
                structure = transparent;
                size      = $aodf-size;
                ACL       = $unprotected;
            }

            BSO secret-pin {
                file-id   = 4101;
                type      = 10;
                structure = linear-fixed;
                record-length = 21;
                size      = 21;
                ACL       = *=NEVER, UPDATE=SCB1, DELETE-SELF=SCB3;
            }

            EF secret-key {
                file-id   = 4102;
                type      = 12;
                structure = linear-variable;
                record-length = 37;
                size      = 444;
                ACL       = *=NEVER, UPDATE=SCB1, CRYPTO=SCB1, GENERATE=SCB1, DELETE-SELF=SCB3;
            }

            EF secenv {
                file-id   = 4103;
                type      = 28;
                structure = linear-variable;
                record-length = 56;
                size      = 448;
                ACL       = *=NEVER, READ=NONE, UPDATE=SCB3, DELETE-SELF=SCB3;
            }

            EF template-private-key {
                file-id   = 00A0;
                type      = 9;
                structure = transparent;
                ACL = *=SCB1, READ=NEVER, LOCK=NEVER;
                prop-attr = 0101;
            }

            # This template defines files for keys, certificates etc.
            #
            # When instantiating the template, each file id will be
            # combined with the last octet of the object's pkcs15 id
            # to form a unique file ID.
            template key-domain {
                # This is a dummy entry - pkcs15-init insists that
                # this is present
                EF private-key {
                    file-id   = 00A0;
                    type      = 9;
                    structure = transparent;
                    ACL = *=SCB1, READ=NEVER, LOCK=NEVER;
                }
                EF public-key {
                    file-id   = 00D0;
                    type      = 9;
                    structure = transparent;
                    ACL = *=SCB1, READ=NONE, LOCK=NEVER;
                }
                EF secret-key {
                    file-id   = 4102;
                    type      = 12;
                    structure = linear-variable;
                    record-length = 37;
                    size      = 444;
                    ACL       = *=NEVER, UPDATE=SCB1, CRYPTO=SCB1, GENERATE=SCB1, DELETE-SELF=SCB3;
                }
            }
        }
    }
}
