import { AskarModule, transformSeedToPrivateJwk } from '@credo-ts/askar'
import type {
  DcqlQuery,
  DifPresentationExchangeDefinitionV2,
  DidKey,
  X509Certificate,
} from '@credo-ts/core'
import {
  ClaimFormat,
  ConsoleLogger,
  CredoError,
  Kms,
  LogLevel,
  TypedArrayEncoder,
  utils,
  X509Module,
  X509Service,
} from '@credo-ts/core'
import { NodeInMemoryKeyManagementStorage, NodeKeyManagementService } from '@credo-ts/node'
import {
  type OpenId4VcIssuerModuleConfigOptions,
  OpenId4VcIssuerRecord,
  type OpenId4VciAuthorizationServerConfig,
  type OpenId4VciCredentialConfigurationsSupportedWithFormats,
  OpenId4VciCredentialFormatProfile,
  type OpenId4VciCredentialRequestToCredentialMapper,
  type OpenId4VciSignSdJwtCredentials,
  OpenId4VcModule,
  OpenId4VcVerifierApi,
  type OpenId4VcVerifierModuleConfigOptions,
  OpenId4VcVerifierRecord,
  type OpenId4VcIssuanceSessionStateChangedEvent,
  OpenId4VcIssuerEvents,
  type VerifiedOpenId4VcCredentialHolderBinding,
  OpenId4VcVerifierEvents,
  type OpenId4VcVerificationSessionStateChangedEvent,
  type OpenId4VciSignMdocCredentials,
  type OpenId4VpVersion,
  OpenId4VcVerificationSessionState,
} from '@credo-ts/openid4vc'
import { askar } from '@openwallet-foundation/askar-nodejs'
import { decodeJwt } from 'jose'
import { BaseAgent } from './BaseAgent'
import { Output } from './OutputClass'

const PROVIDER_HOST = process.env.PROVIDER_HOST ?? 'http://localhost:3042'
const ISSUER_HOST = process.env.ISSUER_HOST ?? 'https://29e7-27-147-191-147.ngrok-free.app'

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET
export const GOOGLE_ENABLED = GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET

export const credentialConfigurationsSupported = {
  "UniversityDegreeCredential-sdjwt": {
    format: OpenId4VciCredentialFormatProfile.SdJwtDc,
    vct: 'IdentityCredential',
    scope: 'openid4vc:credential:IdentityCredential',
    cryptographic_binding_methods_supported: ['jwk', 'did:jwk', 'did:key'],
    credential_signing_alg_values_supported: [
      Kms.KnownJwaSignatureAlgorithms.ES256,
      Kms.KnownJwaSignatureAlgorithms.EdDSA,
    ],
    proof_types_supported: {
      jwt: {
        proof_signing_alg_values_supported: [
          Kms.KnownJwaSignatureAlgorithms.ES256,
          Kms.KnownJwaSignatureAlgorithms.EdDSA,
        ],
      },
    },
  },
  "eu.europa.ec.eudi.pid_mdoc": {
    format: OpenId4VciCredentialFormatProfile.MsoMdoc,
    "scope": "eu.europa.ec.eudi.pid.mdoc",
    "cryptographic_binding_methods_supported": [
      "jwk"
    ],
    "credential_signing_alg_values_supported": [
      Kms.KnownCoseSignatureAlgorithms.Ed25519,
      Kms.KnownCoseSignatureAlgorithms.ESP256,
    ],
    "proof_types_supported": {
      "jwt": {
        "proof_signing_alg_values_supported": [
          "ES256"
        ]
      },
      "attestation": {
        "proof_signing_alg_values_supported": [
          "ES256"
        ]
      }
    },
    "credential_metadata": {
      "display": [
        {
          "name": "EU Digital Identity - Person Identification Data",
          "locale": "en",
          "background_color": "#003399",
          "text_color": "#FFFFFF"
        }
      ]
    },
    "doctype": "eu.europa.ec.eudi.pid.1",
    "claims": [
      {
        "path": [
          "eu.europa.ec.eudi.pid.1",
          "family_name"
        ],
        "display": [
          {
            "name": "Family Name",
            "locale": "en"
          }
        ]
      },
      {
        "path": [
          "eu.europa.ec.eudi.pid.1",
          "given_name"
        ],
        "display": [
          {
            "name": "Given Name",
            "locale": "en"
          }
        ]
      },
      {
        "path": [
          "eu.europa.ec.eudi.pid.1",
          "birth_date"
        ],
        "display": [
          {
            "name": "Date of Birth",
            "locale": "en"
          }
        ]
      },
      {
        "path": [
          "eu.europa.ec.eudi.pid.1",
          "birth_place"
        ],
        "display": [
          {
            "name": "Place of Birth",
            "locale": "en"
          }
        ]
      },
      {
        "path": [
          "eu.europa.ec.eudi.pid.1",
          "nationality"
        ],
        "display": [
          {
            "name": "Nationality",
            "locale": "en"
          }
        ]
      },
      {
        "path": [
          "eu.europa.ec.eudi.pid.1",
          "expiry_date"
        ],
        "display": [
          {
            "name": "Date of Expiry",
            "locale": "en"
          }
        ]
      },
      {
        "path": [
          "eu.europa.ec.eudi.pid.1",
          "issuing_authority"
        ],
        "display": [
          {
            "name": "Issuing Authority",
            "locale": "en"
          }
        ]
      },
      {
        "path": [
          "eu.europa.ec.eudi.pid.1",
          "issuing_country"
        ],
        "display": [
          {
            "name": "Issuing Country",
            "locale": "en"
          }
        ]
      },
      {
        "path": [
          "eu.europa.ec.eudi.pid.1",
          "personal_administrative_number"
        ],
        "display": [
          {
            "name": "Personal Administrative Number",
            "locale": "en"
          }
        ]
      },
      {
        "path": [
          "eu.europa.ec.eudi.pid.1",
          "portrait"
        ],
        "display": [
          {
            "name": "Portrait",
            "locale": "en"
          }
        ]
      },
      {
        "path": [
          "eu.europa.ec.eudi.pid.1",
          "family_name_birth"
        ],
        "display": [
          {
            "name": "Family Name at Birth",
            "locale": "en"
          }
        ]
      },
      {
        "path": [
          "eu.europa.ec.eudi.pid.1",
          "given_name_birth"
        ],
        "display": [
          {
            "name": "Given Name at Birth",
            "locale": "en"
          }
        ]
      },
      {
        "path": [
          "eu.europa.ec.eudi.pid.1",
          "sex"
        ],
        "display": [
          {
            "name": "Sex",
            "locale": "en"
          }
        ]
      },
      {
        "path": [
          "eu.europa.ec.eudi.pid.1",
          "email_address"
        ],
        "display": [
          {
            "name": "Email",
            "locale": "en"
          }
        ]
      },
      {
        "path": [
          "eu.europa.ec.eudi.pid.1",
          "mobile_phone_number"
        ],
        "display": [
          {
            "name": "Phone Number",
            "locale": "en"
          }
        ]
      },
      {
        "path": [
          "eu.europa.ec.eudi.pid.1",
          "resident_address"
        ],
        "display": [
          {
            "name": "Resident Address",
            "locale": "en"
          }
        ]
      },
      {
        "path": [
          "eu.europa.ec.eudi.pid.1",
          "resident_country"
        ],
        "display": [
          {
            "name": "Resident Country",
            "locale": "en"
          }
        ]
      },
      {
        "path": [
          "eu.europa.ec.eudi.pid.1",
          "resident_state"
        ],
        "display": [
          {
            "name": "Resident State",
            "locale": "en"
          }
        ]
      },
      {
        "path": [
          "eu.europa.ec.eudi.pid.1",
          "resident_city"
        ],
        "display": [
          {
            "name": "Resident City",
            "locale": "en"
          }
        ]
      },
      {
        "path": [
          "eu.europa.ec.eudi.pid.1",
          "resident_postal_code"
        ],
        "display": [
          {
            "name": "Resident Postal Code",
            "locale": "en"
          }
        ]
      },
      {
        "path": [
          "eu.europa.ec.eudi.pid.1",
          "resident_street"
        ],
        "display": [
          {
            "name": "Resident Street",
            "locale": "en"
          }
        ]
      },
      {
        "path": [
          "eu.europa.ec.eudi.pid.1",
          "resident_house_number"
        ],
        "display": [
          {
            "name": "Resident House Number",
            "locale": "en"
          }
        ]
      },
      {
        "path": [
          "eu.europa.ec.eudi.pid.1",
          "document_number"
        ],
        "display": [
          {
            "name": "Document Number",
            "locale": "en"
          }
        ]
      },
      {
        "path": [
          "eu.europa.ec.eudi.pid.1",
          "issuing_jurisdiction"
        ],
        "display": [
          {
            "name": "Issuing Jurisdiction",
            "locale": "en"
          }
        ]
      },
      {
        "path": [
          "eu.europa.ec.eudi.pid.1",
          "issuance_date"
        ],
        "display": [
          {
            "name": "Date of Issuance",
            "locale": "en"
          }
        ]
      }
    ]
  },
  // "org.iso.18013.5.1.mDL": {
  //     "format": "mso_mdoc",
  //     "scope": "org.iso.18013.5.1.mDL",
  //     "cryptographic_binding_methods_supported": [
  //       "jwk"
  //     ],
  //     "credential_signing_alg_values_supported": [
  //       Kms.KnownCoseSignatureAlgorithms.Ed25519,
  //       Kms.KnownCoseSignatureAlgorithms.ESP256,
  //     ],
  //     "proof_types_supported": {
  //       "jwt": {
  //         "proof_signing_alg_values_supported": [
  //           "ES256"
  //         ]
  //       },
  //       "attestation": {
  //         "proof_signing_alg_values_supported": [
  //           "ES256"
  //         ]
  //       }
  //     },
  //     "credential_metadata": {
  //       "display": [
  //         {
  //           "name": "Mobile Driving Licence (mDL)",
  //           "locale": "en",
  //           "background_color": "#1a472a",
  //           "text_color": "#FFFFFF"
  //         }
  //       ]
  //     },
  //     "doctype": "org.iso.18013.5.1.mDL",
  //     "claims": [
  //       {
  //         "path": [
  //           "org.iso.18013.5.1",
  //           "family_name"
  //         ],
  //         "display": [
  //           {
  //             "name": "Family Name",
  //             "locale": "en"
  //           }
  //         ]
  //       },
  //       {
  //         "path": [
  //           "org.iso.18013.5.1",
  //           "given_name"
  //         ],
  //         "display": [
  //           {
  //             "name": "Given Names",
  //             "locale": "en"
  //           }
  //         ]
  //       },
  //       {
  //         "path": [
  //           "org.iso.18013.5.1",
  //           "birth_date"
  //         ],
  //         "display": [
  //           {
  //             "name": "Date of Birth",
  //             "locale": "en"
  //           }
  //         ]
  //       },
  //       {
  //         "path": [
  //           "org.iso.18013.5.1",
  //           "issue_date"
  //         ],
  //         "display": [
  //           {
  //             "name": "Date of Issue",
  //             "locale": "en"
  //           }
  //         ]
  //       },
  //       {
  //         "path": [
  //           "org.iso.18013.5.1",
  //           "expiry_date"
  //         ],
  //         "display": [
  //           {
  //             "name": "Date of Expiry",
  //             "locale": "en"
  //           }
  //         ]
  //       },
  //       {
  //         "path": [
  //           "org.iso.18013.5.1",
  //           "issuing_country"
  //         ],
  //         "display": [
  //           {
  //             "name": "Issuing Country",
  //             "locale": "en"
  //           }
  //         ]
  //       },
  //       {
  //         "path": [
  //           "org.iso.18013.5.1",
  //           "issuing_authority"
  //         ],
  //         "display": [
  //           {
  //             "name": "Issuing Authority",
  //             "locale": "en"
  //           }
  //         ]
  //       },
  //       {
  //         "path": [
  //           "org.iso.18013.5.1",
  //           "document_number"
  //         ],
  //         "display": [
  //           {
  //             "name": "Licence Number",
  //             "locale": "en"
  //           }
  //         ]
  //       },
  //       {
  //         "path": [
  //           "org.iso.18013.5.1",
  //           "portrait"
  //         ],
  //         "display": [
  //           {
  //             "name": "Portrait",
  //             "locale": "en"
  //           }
  //         ]
  //       },
  //       {
  //         "path": [
  //           "org.iso.18013.5.1",
  //           "driving_privileges"
  //         ],
  //         "display": [
  //           {
  //             "name": "Driving Privileges",
  //             "locale": "en"
  //           }
  //         ]
  //       },
  //       {
  //         "path": [
  //           "org.iso.18013.5.1",
  //           "un_distinguishing_sign"
  //         ],
  //         "display": [
  //           {
  //             "name": "UN Distinguishing Sign",
  //             "locale": "en"
  //           }
  //         ]
  //       },
  //       {
  //         "path": [
  //           "org.iso.18013.5.1",
  //           "administrative_number"
  //         ],
  //         "display": [
  //           {
  //             "name": "Administrative Number",
  //             "locale": "en"
  //           }
  //         ]
  //       },
  //       {
  //         "path": [
  //           "org.iso.18013.5.1",
  //           "sex"
  //         ],
  //         "display": [
  //           {
  //             "name": "Sex",
  //             "locale": "en"
  //           }
  //         ]
  //       },
  //       {
  //         "path": [
  //           "org.iso.18013.5.1",
  //           "height"
  //         ],
  //         "display": [
  //           {
  //             "name": "Height (cm)",
  //             "locale": "en"
  //           }
  //         ]
  //       },
  //       {
  //         "path": [
  //           "org.iso.18013.5.1",
  //           "weight"
  //         ],
  //         "display": [
  //           {
  //             "name": "Weight (kg)",
  //             "locale": "en"
  //           }
  //         ]
  //       },
  //       {
  //         "path": [
  //           "org.iso.18013.5.1",
  //           "eye_colour"
  //         ],
  //         "display": [
  //           {
  //             "name": "Eye Colour",
  //             "locale": "en"
  //           }
  //         ]
  //       },
  //       {
  //         "path": [
  //           "org.iso.18013.5.1",
  //           "hair_colour"
  //         ],
  //         "display": [
  //           {
  //             "name": "Hair Colour",
  //             "locale": "en"
  //           }
  //         ]
  //       },
  //       {
  //         "path": [
  //           "org.iso.18013.5.1",
  //           "birth_place"
  //         ],
  //         "display": [
  //           {
  //             "name": "Place of Birth",
  //             "locale": "en"
  //           }
  //         ]
  //       },
  //       {
  //         "path": [
  //           "org.iso.18013.5.1",
  //           "resident_address"
  //         ],
  //         "display": [
  //           {
  //             "name": "Permanent Place of Residence",
  //             "locale": "en"
  //           }
  //         ]
  //       },
  //       {
  //         "path": [
  //           "org.iso.18013.5.1",
  //           "portrait_capture_date"
  //         ],
  //         "display": [
  //           {
  //             "name": "Portrait Capture Date",
  //             "locale": "en"
  //           }
  //         ]
  //       },
  //       {
  //         "path": [
  //           "org.iso.18013.5.1",
  //           "age_in_years"
  //         ],
  //         "display": [
  //           {
  //             "name": "Age in Years",
  //             "locale": "en"
  //           }
  //         ]
  //       },
  //       {
  //         "path": [
  //           "org.iso.18013.5.1",
  //           "age_birth_year"
  //         ],
  //         "display": [
  //           {
  //             "name": "Year of Birth",
  //             "locale": "en"
  //           }
  //         ]
  //       },
  //       {
  //         "path": [
  //           "org.iso.18013.5.1",
  //           "age_over_18"
  //         ],
  //         "display": [
  //           {
  //             "name": "Age Over 18",
  //             "locale": "en"
  //           }
  //         ]
  //       },
  //       {
  //         "path": [
  //           "org.iso.18013.5.1",
  //           "age_over_21"
  //         ],
  //         "display": [
  //           {
  //             "name": "Age Over 21",
  //             "locale": "en"
  //           }
  //         ]
  //       },
  //       {
  //         "path": [
  //           "org.iso.18013.5.1",
  //           "issuing_jurisdiction"
  //         ],
  //         "display": [
  //           {
  //             "name": "Issuing Jurisdiction",
  //             "locale": "en"
  //           }
  //         ]
  //       }
  //     ]
  //   },
  "eu.europa.ec.eudi.pid_sdjwt": {
    format: OpenId4VciCredentialFormatProfile.SdJwtDc,
    vct: 'eu.europa.ec.eudi.pid.1',
    // vct: 'urn:eudi:pid:1',
    scope: 'openid4vc:credential:eu.europa.ec.eudi.pid.1',
    cryptographic_binding_methods_supported: ['jwk', 'did:jwk', 'did:key'],
    credential_signing_alg_values_supported: [
      Kms.KnownJwaSignatureAlgorithms.ES256,
      Kms.KnownJwaSignatureAlgorithms.EdDSA,
    ],
    proof_types_supported: {
      jwt: {
        proof_signing_alg_values_supported: [
          Kms.KnownJwaSignatureAlgorithms.ES256,
          Kms.KnownJwaSignatureAlgorithms.EdDSA,
        ],
      },
    },
    credential_metadata: {
      display: [
        {
          name: "EU Digital Identity - Person Identification Data",
          locale: "en",
          background_color: "#003399",
          text_color: "#FFFFFF"
        }
      ]
    },
    "claims": [
      {
        "path": [
          "family_name"
        ],
        "display": [
          {
            "name": "Family Name",
            "locale": "en"
          }
        ]
      },
      {
        "path": [
          "given_name"
        ],
        "display": [
          {
            "name": "Given Name",
            "locale": "en"
          }
        ]
      },
      {
        "path": [
          "birth_date"
        ],
        "display": [
          {
            "name": "Date of Birth",
            "locale": "en"
          }
        ]
      },
      {
        "path": [
          "birth_place"
        ],
        "display": [
          {
            "name": "Place of Birth",
            "locale": "en"
          }
        ]
      },
      {
        "path": [
          "nationality"
        ],
        "display": [
          {
            "name": "Nationality",
            "locale": "en"
          }
        ]
      },
      {
        "path": [
          "expiry_date"
        ],
        "display": [
          {
            "name": "Date of Expiry",
            "locale": "en"
          }
        ]
      },
      {
        "path": [
          "issuing_authority"
        ],
        "display": [
          {
            "name": "Issuing Authority",
            "locale": "en"
          }
        ]
      },
      {
        "path": [
          "issuing_country"
        ],
        "display": [
          {
            "name": "Issuing Country",
            "locale": "en"
          }
        ]
      },
      {
        "path": [
          "personal_administrative_number"
        ],
        "display": [
          {
            "name": "Personal Administrative Number",
            "locale": "en"
          }
        ]
      },
      {
        "path": [
          "portrait"
        ],
        "display": [
          {
            "name": "Portrait",
            "locale": "en"
          }
        ]
      },
      {
        "path": [
          "family_name_birth"
        ],
        "display": [
          {
            "name": "Family Name at Birth",
            "locale": "en"
          }
        ]
      },
      {
        "path": [
          "given_name_birth"
        ],
        "display": [
          {
            "name": "Given Name at Birth",
            "locale": "en"
          }
        ]
      },
      {
        "path": [
          "sex"
        ],
        "display": [
          {
            "name": "Sex",
            "locale": "en"
          }
        ]
      },
      {
        "path": [
          "email_address"
        ],
        "display": [
          {
            "name": "Email",
            "locale": "en"
          }
        ]
      },
      {
        "path": [
          "mobile_phone_number"
        ],
        "display": [
          {
            "name": "Phone Number",
            "locale": "en"
          }
        ]
      },
      {
        "path": [
          "resident_address"
        ],
        "display": [
          {
            "name": "Resident Address",
            "locale": "en"
          }
        ]
      },
      {
        "path": [
          "resident_country"
        ],
        "display": [
          {
            "name": "Resident Country",
            "locale": "en"
          }
        ]
      },
      {
        "path": [
          "resident_state"
        ],
        "display": [
          {
            "name": "Resident State",
            "locale": "en"
          }
        ]
      },
      {
        "path": [
          "resident_city"
        ],
        "display": [
          {
            "name": "Resident City",
            "locale": "en"
          }
        ]
      },
      {
        "path": [
          "resident_postal_code"
        ],
        "display": [
          {
            "name": "Resident Postal Code",
            "locale": "en"
          }
        ]
      },
      {
        "path": [
          "resident_street"
        ],
        "display": [
          {
            "name": "Resident Street",
            "locale": "en"
          }
        ]
      },
      {
        "path": [
          "resident_house_number"
        ],
        "display": [
          {
            "name": "Resident House Number",
            "locale": "en"
          }
        ]
      },
      {
        "path": [
          "document_number"
        ],
        "display": [
          {
            "name": "Document Number",
            "locale": "en"
          }
        ]
      },
      {
        "path": [
          "issuing_jurisdiction"
        ],
        "display": [
          {
            "name": "Issuing Jurisdiction",
            "locale": "en"
          }
        ]
      },
      {
        "path": [
          "issuance_date"
        ],
        "display": [
          {
            "name": "Date of Issuance",
            "locale": "en"
          }
        ]
      }
    ]
  },
  "urn:eu.europa.ec.eudi:learning:credential:1": {
    format: OpenId4VciCredentialFormatProfile.SdJwtDc,
    vct: 'urn:eu.europa.ec.eudi:learning:credential:1',
    scope: 'openid4vc:credential:urn:eu.europa.ec.eudi:learning:credential:1',
    cryptographic_binding_methods_supported: ['jwk', 'did:jwk', 'did:key'],
    credential_signing_alg_values_supported: [
      Kms.KnownJwaSignatureAlgorithms.ES256,
    ],
    proof_types_supported: {
      jwt: {
        proof_signing_alg_values_supported: [
          Kms.KnownJwaSignatureAlgorithms.ES256,
        ],
      },
    },
    credential_metadata: {
      display: [
        {
          name: "EU Digital Identity - Learning Credential",
          locale: "en",
          background_color: "#003399",
          text_color: "#FFFFFF"
        }
      ],
      "claims": [
        {
          path: ["issuing_authority"]
        },
        {
          path: ["issuing_country"]
        },
        {
          "path": [
            "date_of_issuance"
          ]
        },
        {
          path: ["date_of_expiry"]
        },
        {
          "path": [
            "family_name"
          ]
        },
        {
          "path": [
            "achievement_title"
          ]
        },
        {
          path: ["achievement_description"]
        },
        {
          "path": [
            "learning_outcomes"
          ]
        },
        {
          "path": [
            "assessment_grade"
          ]
        }
      ]
    }
  }
} satisfies OpenId4VciCredentialConfigurationsSupportedWithFormats

const presentationAuthorizationDcql = {
  credential_sets: [
    {
      required: true,
      options: [['UniversityDegreeCredential-sdjwt-dc']],
    },
  ],
  credentials: [
    {
      id: 'UniversityDegreeCredential-sdjwt-dc',
      format: 'dc+sd-jwt',
      meta: {
        vct_values: [credentialConfigurationsSupported["UniversityDegreeCredential-sdjwt"].vct],
      },
    },
  ],
} satisfies DcqlQuery

export const pidPex = {
  "id": "71f807df-ad38-4a8f-8fd4-491e3152495c",
  "name": "EUDI PID",
  "purpose": "EUDI PID",
  "input_descriptors": [
    {
      "id": "eu.europa.ec.eudi.pid.1",
      "format": {
        "mso_mdoc": {
          "alg": [
            "ES256",
            "ES384",
            "ES512"
          ]
        }
      },
      "constraints": {
        "limit_disclosure": "required",
        "fields": [
          {
            "intent_to_retain": false,
            "path": [
              "$['eu.europa.ec.eudi.pid.1']['given_name']"
            ]
          },
          {
            "intent_to_retain": false,
            "path": [
              "$['eu.europa.ec.eudi.pid.1']['family_name']"
            ]
          },
          {
            "path": [
              "$['eu.europa.ec.eudi.pid.1']['birth_date']"
            ],
            "intent_to_retain": false
          },
          {
            "path": [
              "$['eu.europa.ec.eudi.pid.1']['birth_place']"
            ],
            "intent_to_retain": false
          }

        ]
      }
    }
  ]
} satisfies DifPresentationExchangeDefinitionV2


/** DCQL used for standalone verification requests (presentation). Matches issued UniversityDegreeCredential. */
export const verificationDcql = {
  "credentials": [
    {
      "id": "2",
      "format": "mso_mdoc",
      "meta": {
        "doctype_value": "eu.europa.ec.eudi.pid.1"
      },
      "claims": [
        {
          "id": "given_name",
          "path": [
            "eu.europa.ec.eudi.pid.1",
            "given_name"
          ],
          "intent_to_retain": false
        },
        {
          "id": "family_name",
          "path": [
            "eu.europa.ec.eudi.pid.1",
            "family_name"
          ],
          "intent_to_retain": false
        },
        // {
        //   "id": "birth_date",
        //   "path": [
        //     "eu.europa.ec.eudi.pid.1",
        //     "birth_date"
        //   ],
        //   "intent_to_retain": false
        // }
      ]
    }
  ],
  "credential_sets": [
    {
      "options": [
        [
          "2"
        ]
      ],
    }
  ]
} satisfies DcqlQuery

export const verificationDcqlSdjwt = {
  "credentials": [
    {
      "id": "2",
      "format": "dc+sd-jwt",
      "meta": {
        "vct_values": ["eu.europa.ec.eudi.pid.1"]
      },
      "claims": [
        {
          "path": [
            "given_name"
          ],
        },
        {
          "path": [
            "family_name"
          ],
        },
        // {
        //   "id": "birth_date",
        //   "path": [
        //     "eu.europa.ec.eudi.pid.1",
        //     "birth_date"
        //   ],
        //   "intent_to_retain": false
        // }
      ]
    }
  ],
  "credential_sets": [
    {
      "options": [
        [
          "2"
        ]
      ],
    }
  ]
} satisfies DcqlQuery

let issuerCertificate: X509Certificate

function getCredentialRequestToCredentialMapper({
  issuerDidKey,
}: {
  issuerDidKey: DidKey
}): OpenId4VciCredentialRequestToCredentialMapper {
  return async ({
    holderBinding,
    credentialConfigurationId,
    credentialConfiguration,
    authorization,
    issuanceSession,
  }) => {
    // Example of how to use the the access token information from the chained identity server.
    let authorizedUser = authorization.accessToken.payload.sub

    if (typeof issuanceSession.chainedIdentity?.externalAccessTokenResponse?.id_token === 'string') {
      // This token has already been validated by Credo, so we can just decode it.
      const claims = decodeJwt(issuanceSession.chainedIdentity.externalAccessTokenResponse.id_token)
      if (typeof claims.email === 'string') {
        authorizedUser = claims.email
      }
    }

    if (credentialConfigurationId === 'UniversityDegreeCredential-sdjwt') {
      console.log("holderBinding", JSON.stringify(holderBinding, null, 2))
      return {
        type: 'credentials',
        format: ClaimFormat.SdJwtDc,
        credentials: holderBinding.keys.map((binding) => ({
          payload: {
            vct: credentialConfiguration.vct as string,
            name: 'John Doe',
          },
          holder: binding,
          issuer:
            binding.method === 'did'
              ? {
                method: 'did',
                didUrl: `${issuerDidKey.did}#${issuerDidKey.publicJwk.fingerprint}`,
              }
              : { method: 'x5c', x5c: [issuerCertificate], issuer: ISSUER_HOST },
        })),
      } satisfies OpenId4VciSignSdJwtCredentials
    }

    if (credentialConfigurationId === 'eu.europa.ec.eudi.pid_sdjwt') {
      return {
        type: 'credentials',
        format: ClaimFormat.SdJwtDc,
        credentials: holderBinding.keys.map((binding) => ({
          payload: {
            vct: credentialConfiguration.vct as string,
            given_name: 'John',
            family_name: 'Doe',
            birth_date: '1990/01/01',
            birthdate: '1990/01/01',
            place_of_birth: {
              country: "Finland",
              region: "Helsinki",
              locality: "Helsinki",
            },
            nationalities: ["Finland"],
            date_of_expiry: '2026/01/01',
            issuing_authority: "Finland",
            issuing_country: "Finland",
            sex: "Male",
            email: "john.doe@example.com",
            phone_number: "1234567890",
            address: {
              country: "Finland",
              region: "Helsinki",
              locality: "Helsinki",
              street_address: "Main Street 1",
              postal_code: "00100",
              house_number: "1",
            },
            document_number: "1234567890",
            issuing_jurisdiction: "Finland",
            issuance_date: '2026/01/01',
          },
          holder: binding,
          issuer:
            binding.method === 'did'
              ? {
                method: 'did',
                didUrl: `${issuerDidKey.did}#${issuerDidKey.publicJwk.fingerprint}`,
              }
              : { method: 'x5c', x5c: [issuerCertificate], issuer: ISSUER_HOST },
        })),
      } satisfies OpenId4VciSignSdJwtCredentials
    }

    if (credentialConfigurationId === 'eu.europa.ec.eudi.pid_mdoc') {
      const credentialResponse = {
        type: 'credentials',
        format: ClaimFormat.MsoMdoc as const,
        credentials: holderBinding.keys.map((binding) => (
          {
            issuerCertificate: issuerCertificate,
            holderKey: binding.jwk,
            namespaces: {
              "eu.europa.ec.eudi.pid.1": {
                given_name: 'John',
                family_name: 'Doe',
                birth_date: '1990/01/01',
                birthdate: '1990/01/01',
                birth_place: 'Helsinki',
                place_of_birth: {
                  country: "Finland",
                  region: "Helsinki",
                  locality: "Helsinki",
                },
                nationalities: ["Finland"],
                date_of_expiry: '2026/01/01',
                issuing_authority: "Finland",
                issuing_country: "Finland",
                sex: "Male",
                email: "john.doe@example.com",
                phone_number: "1234567890",
                address: {
                  country: "Finland",
                  region: "Helsinki",
                  locality: "Helsinki",
                  street_address: "Main Street 1",
                  postal_code: "00100",
                  house_number: "1",
                },
                document_number: "1234567890",
                issuing_jurisdiction: "Finland",
                issuance_date: '2026/01/01',
              }
            },
            docType: credentialConfiguration.doctype as string
          }
        ))
      } satisfies OpenId4VciSignMdocCredentials
      return credentialResponse
    }

    if (credentialConfigurationId === 'urn:eu.europa.ec.eudi:learning:credential:1') {
      return {
        type: 'credentials',
        format: ClaimFormat.SdJwtDc,
        credentials: holderBinding.keys.map((binding) => ({
          payload: {
            vct: credentialConfiguration.vct as string,
            issuing_authority: 'EU Digital Identity',
            issuing_country: 'EU',
            date_of_issuance: '2026/01/01',
            date_of_expiry: '2026/01/01',
            family_name: 'Doe',
            given_name: 'John',
            achievement_title: 'Bachelor of Science in Computer Science',
            achievement_description: 'Bachelor of Science in Computer Science',
            learning_outcomes: [
              "Learned how to code",
            ],
            assessment_grade: 'A',
          },
          holder: binding,
          issuer:
            binding.method === 'did'
              ? {
                method: 'did',
                didUrl: `${issuerDidKey.did}#${issuerDidKey.publicJwk.fingerprint}`,
              }
              : { method: 'x5c', x5c: [issuerCertificate], issuer: ISSUER_HOST },
        })),
      } satisfies OpenId4VciSignSdJwtCredentials
    }

    // if(credentialConfigurationId === 'org.iso.18013.5.1.mDL') {
    //   const credentialResponse = {
    //     type: 'credentials',
    //     format: ClaimFormat.MsoMdoc as const,
    //     credentials: holderBinding.keys.map((binding) => (
    //       {
    //         issuerCertificate: issuerCertificate,
    //           holderKey: binding.jwk,
    //         namespaces: {
    //           "org.iso.18013.5.1": {
    //             family_name: 'Jones',
    //             given_name: 'Ava',
    //             birth_date: '2007/03/25',
    //             issue_date: '2023/09/01',
    //             expiry_date: '2028/09/31',
    //             issuing_country: 'US',
    //             issuing_authority: 'NY DMV',
    //             document_number: '01-856-5050',
    //             // portrait: 'bstr',
    //             driving_privileges: [
    //               {
    //                 vehicle_category_code: 'C',
    //                 issue_date: '2023/09/01',
    //                 expiry_date: '2028/09/31',
    //               },
    //             ],
    //             un_distinguishing_sign: 'tbd-us.ny.dmv',
    //             administrative_number: '1234567890',
    //             sex: 'F',
    //             height: '172.72cm',
    //             weight: '72.57kg',
    //             eye_colour: 'brown',
    //             hair_colour: 'brown',
    //             resident_addres: '123 Street Rd',
    //             portrait_capture_date: '2023/09/01',
    //             age_in_years: 30,
    //             age_birth_year: 1990,
    //             age_over_18: true,
    //             age_over_21: true,
    //             birth_place: 'New York',

    //           }
    //         },
    //         docType: credentialConfiguration.doctype as string
    //       }
    //     ))
    //   } satisfies OpenId4VciSignMdocCredentials
    //   return credentialResponse
    // }


    throw new Error('Invalid request')
  }
}

export class Diip extends BaseAgent<{
  askar: AskarModule
  openid4vc: OpenId4VcModule<OpenId4VcIssuerModuleConfigOptions, OpenId4VcVerifierModuleConfigOptions>
}> {
  public issuerRecord!: OpenId4VcIssuerRecord
  public verifierRecord!: OpenId4VcVerifierRecord

  public constructor(url: string, port: number, name: string) {
    super({
      port,
      name,
      modules: (app) => {
        app.all('/callback', (req, res) => {
          console.log('Verification callback received', req.query)
          res.status(200).send('Verification complete. You can close this tab.')
        })
        return {
        askar: new AskarModule({ askar, store: { id: name, key: name } }),
        kms: new Kms.KeyManagementModule({
          backends: [new NodeKeyManagementService(new NodeInMemoryKeyManagementStorage())],
        }),
        openid4vc: new OpenId4VcModule({
          app,
          verifier: {
            authorizationRequestExpirationInSeconds: 3600,
            baseUrl: `${url}/oid4vp`,
          },
          issuer: {
            baseUrl: `${url}/oid4vci`,
            dpopRequired: false,
            cNonceExpiresInSeconds: 3600,
            statefulCredentialOfferExpirationInSeconds: 3600,
            authorizationCodeExpiresInSeconds: 3600,
            accessTokenExpiresInSeconds: 3600,
            refreshTokenExpiresInSeconds: 3600,
            requestUriExpiresInSeconds: 3600,
            credentialRequestToCredentialMapper: (...args) =>
              getCredentialRequestToCredentialMapper({ issuerDidKey: this.didKey })(...args),
          },
        }),
        x509: new X509Module({
          getTrustedCertificatesForVerification: (agentContext, { certificateChain, verification }) => {
            // only support self signed certificate as it takes only leaf certificate
            return [certificateChain[0].toString('pem')]
          },
        }),
        }
      },
    })


    // Listen to issuance session (credential) state changes
    this.agent.events.on<OpenId4VcIssuanceSessionStateChangedEvent>(
      OpenId4VcIssuerEvents.IssuanceSessionStateChanged,
      (event) => {
        const { issuanceSession, previousState } = event.payload
        console.log('Issuance session state changed: ', issuanceSession.state)
        console.log('Issuance session: ', JSON.stringify(issuanceSession, null, 2))
      }
    )
    // Listen to verification session (presentation) state changes
    this.agent.events.on<OpenId4VcVerificationSessionStateChangedEvent>(
      OpenId4VcVerifierEvents.VerificationSessionStateChanged,
      async (event) => {
        const { verificationSession, previousState } = event.payload
        console.log('Verification session state changed: ', verificationSession.state)
        console.log('Verification session: ', JSON.stringify(verificationSession, null, 2))

        if(verificationSession.state === 'ResponseVerified' ) {
          // retrive the verifier session and get the presentation exchange
          const verifierSession = await this.agent.openid4vc.verifier.getVerifiedAuthorizationResponse(verificationSession.id)
          console.log('Verifier session: ', JSON.stringify(verifierSession, null, 2))
        }
      }
    )
  }


  public static async build(): Promise<Diip> {
    const issuer = new Diip(ISSUER_HOST, 2000, `OpenId4VcIssuer ${Math.random().toString()}`)
    await issuer.initializeAgent('96213c3d7fc8d4d6754c7a0fd969598f')

    const importedKey = await issuer.agent.kms.importKey({
      privateJwk: transformSeedToPrivateJwk({
        seed: TypedArrayEncoder.fromString('e5f18b10cd15cdb76818bc6ae8b71eb475e6eac76875ed085d3962239bbcf42f'),
        type: {
          crv: 'P-256',
          kty: 'EC',
        },
      }).privateJwk,
    })
    issuerCertificate = await X509Service.createCertificate(issuer.agent.context, {
      authorityKey: Kms.PublicJwk.fromPublicJwk(importedKey.publicJwk),
      validity: {
        notBefore: new Date('2000-01-01'),
        notAfter: new Date('2050-01-01'),
      },
      extensions: {
        subjectAlternativeName: {
          name: [{ type: 'dns', value: ISSUER_HOST.replace('https://', '').replace('http://', '') }],
        },
      },
      issuer: 'C=FI',
    })


    issuer.agent.x509.config.setTrustedCertificates([issuerCertificate])
    console.log('Set the following certificate for the holder to verify mdoc credentials.')
    console.log(issuerCertificate.toString('base64'))
    console.log(issuerCertificate.toString('pem'))

    issuer.verifierRecord = await issuer.agent.openid4vc.verifier.createVerifier({
      verifierId: '726222ad-7624-4f12-b15b-e08aa7042ffa',
    })
    issuer.issuerRecord = await issuer.agent.openid4vc.issuer.createIssuer({
      issuerId: '726222ad-7624-4f12-b15b-e08aa7042ffa',
      credentialConfigurationsSupported,
      // authorizationServerConfigs: [
      //   {
      //     type: 'direct',
      //     issuer: PROVIDER_HOST,
      //     clientAuthentication: {
      //       clientId: 'issuer-server',
      //       clientSecret: 'issuer-server',
      //     },
      //   },
      //   ...((GOOGLE_ENABLED
      //     ? [
      //         {
      //           type: 'chained',
      //           issuer: 'https://accounts.google.com',
      //           clientAuthentication: {
      //             type: 'clientSecret',
      //             clientId: GOOGLE_CLIENT_ID,
      //             clientSecret: GOOGLE_CLIENT_SECRET,
      //           },
      //           scopesMapping: {
      //             'openid4vc:credential:OpenBadgeCredential': [
      //               'openid',
      //               'https://www.googleapis.com/auth/userinfo.email',
      //             ],
      //           },
      //         },
      //       ]
      //     : []) as OpenId4VciAuthorizationServerConfig[]),
      // ],
    })

    const issuerMetadata = await issuer.agent.openid4vc.issuer.getIssuerMetadata(issuer.issuerRecord.issuerId)
    console.log(`\nIssuer url is ${issuerMetadata.credentialIssuer.credential_issuer}`)

    return issuer
  }

  public async createCredentialOffer(options: {
    credentialConfigurationIds: string[]
    requireAuthorization?: 'presentation' | 'browser' | 'browser-external'
    requirePin: boolean
  }) {
    const issuerMetadata = await this.agent.openid4vc.issuer.getIssuerMetadata(this.issuerRecord.issuerId)

    const { credentialOffer, issuanceSession } = await this.agent.openid4vc.issuer.createCredentialOffer({
      issuerId: this.issuerRecord.issuerId,
      credentialConfigurationIds: options.credentialConfigurationIds,
      // Pre-auth using our own server
      preAuthorizedCodeFlowConfig: !options.requireAuthorization
        ? {
          authorizationServerUrl: issuerMetadata.credentialIssuer.credential_issuer,
          txCode: options.requirePin
            ? {
              input_mode: 'numeric',
              length: 4,
              description: 'Pin has been printed to the terminal',
            }
            : undefined,
        }
        : undefined,
      // Auth using external authorization server
      authorizationCodeFlowConfig: options.requireAuthorization
        ? {
          authorizationServerUrl:
            options.requireAuthorization === 'browser'
              ? PROVIDER_HOST
              : options.requireAuthorization === 'browser-external'
                ? 'https://accounts.google.com'
                : undefined,
          // TODO: should be generated by us, if we're going to use for matching
          issuerState: utils.uuid(),
          requirePresentationDuringIssuance: options.requireAuthorization === 'presentation',
        }
        : undefined,
      // authorization: {
      //   requireDpop: false,
      //   requireWalletAttestation: false,
      // }
    })

    return { credentialOffer, issuanceSession }
  }

  /**
   * Create a verification (proof) request as verifier. Uses DCQL and/or DIF presentation definition.
   */
  public async createProofRequest({
    presentationDefinition,
    dcql,
    version = 'v1'
  }: {
    presentationDefinition?: DifPresentationExchangeDefinitionV2
    dcql?: DcqlQuery,
    version?: OpenId4VpVersion
  }) {
    const { authorizationRequest } = await this.agent.openid4vc.verifier.createAuthorizationRequest({
      verifierId: this.verifierRecord.verifierId,
      requestSigner: {
        method: 'x5c',
        x5c: [issuerCertificate],
      },
      responseMode: 'direct_post.jwt',
      // responseMode: 'dc_api',
      presentationExchange: presentationDefinition
        ? {
          definition: presentationDefinition,
        }
        : undefined,
      dcql: dcql
        ? {
          query: dcql,
        }
        : undefined,
      version: version,
      // expectedOrigins: [ISSUER_HOST],
      authorizationResponseRedirectUri: `${ISSUER_HOST}/callback`
    })
    return authorizationRequest
  }

  public async exit() {
    console.log(Output.Exit)
    await this.shutdown()
    process.exit(0)
  }

  public async restart() {
    await this.shutdown()
  }
}

function assertDidBasedHolderBinding(
  holderBinding: VerifiedOpenId4VcCredentialHolderBinding
): asserts holderBinding is VerifiedOpenId4VcCredentialHolderBinding & { bindingMethod: 'did' } {
  if (holderBinding.bindingMethod !== 'did') {
    throw new CredoError('Only did based holder bindings supported for this credential type')
  }
}

function assertJwkBasedHolderBinding(
  holderBinding: VerifiedOpenId4VcCredentialHolderBinding
): asserts holderBinding is VerifiedOpenId4VcCredentialHolderBinding & { bindingMethod: 'jwk' } {
  if (holderBinding.bindingMethod !== 'jwk') {
    throw new CredoError('Only jwk based holder bindings supported for this credential type')
  }
}

