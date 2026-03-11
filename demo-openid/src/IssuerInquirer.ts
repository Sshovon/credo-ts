import { clear } from 'console'
import figlet from 'figlet'

import { BaseInquirer } from './BaseInquirer'
// import { credentialConfigurationsSupported, GOOGLE_ENABLED  } from './Issuer'
import { credentialConfigurationsSupported, GOOGLE_ENABLED, pidPex, verificationDcql, verificationDcqlSdjwt } from './diip'
import { greenText, purpleText, redText, Title } from './OutputClass'
import { Issuer } from './Issuer'
import { Diip } from './diip'

export const runIssuer = async () => {
  clear()
  console.log(figlet.textSync('Issuer', { horizontalLayout: 'full' }))
  const issuer = await IssuerInquirer.build()
  // await issuer.createStartupCredentialOffer()
  // await issuer.createStartupVerificationRequestMdoc()
  // await issuer.createStartupVerificationRequestSdjwt()
  await issuer.processAnswer()
}

enum PromptOptions {
  CreateCredentialOffer = 'Create a credential offer',
  CreateVerificationRequestMdoc = 'Create a verification request (MDOC)',
  CreateVerificationRequestSdjwt = 'Create a verification request (SDJWT)',
  CreateVerificationRequestMdocPex = 'Create a verification request (PID PEx)',
  Exit = 'Exit',
  Restart = 'Restart',
}

export class IssuerInquirer extends BaseInquirer {
  public issuer: Issuer | Diip

  public constructor(issuer: Issuer | Diip) {
    super()
    this.issuer = issuer
  }

  public static async build(): Promise<IssuerInquirer> {
    const issuer = await Diip.build()
    return new IssuerInquirer(issuer)
  }

  public async processAnswer() {
    const choice = await this.pickOne(Object.values(PromptOptions))

    switch (choice) {
      case PromptOptions.CreateCredentialOffer:
        await this.createCredentialOffer()
        break
      case PromptOptions.CreateVerificationRequestMdoc:
        await this.createStartupVerificationRequestMdoc()
        break
      case PromptOptions.CreateVerificationRequestSdjwt:
        await this.createStartupVerificationRequestSdjwt()
        break
      case PromptOptions.CreateVerificationRequestMdocPex:
        await this.createStartupVerificationRequestMdocPex()
        break
      case PromptOptions.Exit:
        await this.exit()
        break
      case PromptOptions.Restart:
        await this.restart()
        return
    }
    await this.processAnswer()
  }

  public async createStartupCredentialOffer() {
    const credentialConfigurationIds = Object.keys(credentialConfigurationsSupported)
    const { credentialOffer } = await this.issuer.createCredentialOffer({
      credentialConfigurationIds,
      requireAuthorization: undefined,
      requirePin: false,
    })

    console.log(purpleText(`credential offer: '${credentialOffer}'`, true))
  }

  public async createStartupVerificationRequestMdoc() {
    if (!('createProofRequest' in this.issuer) || typeof (this.issuer as Diip).createProofRequest !== 'function') {
      return
    }
    const proofRequest = await (this.issuer as Diip).createProofRequest({
      dcql: verificationDcql,
    })
    console.log(purpleText(`Verification request (DCQL): '${proofRequest}'`, true))
  }

  public async createStartupVerificationRequestMdocPex() {
    if (!('createProofRequest' in this.issuer) || typeof (this.issuer as Diip).createProofRequest !== 'function') {
      return
    }
    const proofRequest = await (this.issuer as Diip).createProofRequest({
      // dcql: verificationDcql,
      presentationDefinition: pidPex,
      version: 'v1.draft21'
    })
    console.log(purpleText(`Verification request (DIF presentation definition): '${proofRequest}'`, true))
  }
  public async createStartupVerificationRequestSdjwt() {
    if (!('createProofRequest' in this.issuer) || typeof (this.issuer as Diip).createProofRequest !== 'function') {
      return
    }
    const proofRequest = await (this.issuer as Diip).createProofRequest({
      dcql: verificationDcqlSdjwt,
    })
    console.log(purpleText(`Verification request (DCQL): '${proofRequest}'`, true))
  }

  public async createCredentialOffer() {
    let credentialConfigurationIds = await this.pickMultiple(Object.keys(credentialConfigurationsSupported))
    while (credentialConfigurationIds.length === 0) {
      console.log(redText('Pick at least one', true))
      credentialConfigurationIds = await this.pickMultiple(Object.keys(credentialConfigurationsSupported))
    }

    const authorizationMethod = await this.pickOne(
      ['Transaction Code', 'Browser', ...(GOOGLE_ENABLED ? ['Browser (Google Account)'] : []), 'Presentation', 'None'],
      'Authorization method'
    )
    const { credentialOffer, issuanceSession } = await this.issuer.createCredentialOffer({
      credentialConfigurationIds,
      requireAuthorization:
        authorizationMethod === 'Browser'
          ? 'browser'
          : authorizationMethod === 'Browser (Google Account)'
            ? 'browser-external'
            : authorizationMethod === 'Presentation'
              ? 'presentation'
              : undefined,
      requirePin: authorizationMethod === 'Transaction Code',
    })

    console.log(purpleText(`credential offer: '${credentialOffer}'`, true))

    if (issuanceSession.userPin) {
      console.log(greenText(`\nEnter PIN ${issuanceSession.userPin} when asked`, true))
    }
  }

  public async exit() {
    if (await this.inquireConfirmation(Title.ConfirmTitle)) {
      await this.issuer.exit()
    }
  }

  public async restart() {
    const confirmed = await this.inquireConfirmation(Title.ConfirmTitle)
    if (confirmed) {
      await this.issuer.restart()
      await runIssuer()
    } else {
      await this.processAnswer()
    }
  }
}

void runIssuer()
