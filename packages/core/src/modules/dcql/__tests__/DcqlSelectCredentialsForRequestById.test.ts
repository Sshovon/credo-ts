import { CredentialMultiInstanceState } from '../../../utils/credentialUse'
import { ClaimFormat } from '../../vc'
import { DcqlError } from '../DcqlError'
import { DcqlService } from '../DcqlService'
import type { DcqlQueryResult } from '../models'

const dcqlService = new DcqlService()

const record = (id: string) => ({
  id,
  type: 'SdJwtVcRecord',
  multiInstanceState: CredentialMultiInstanceState.SingleInstanceUsed,
  credentialInstances: [{}],
})

const validCredential = (recordId: string) => ({
  record: record(recordId),
  claims: { success: true, valid_claim_sets: [{ output: { name: recordId } }] },
})

/**
 * Builds the result of a DCQL query from the ids of the records that are valid, and that failed, for each
 * DCQL credential id.
 */
function queryResult(
  matches: Record<string, { valid?: string[]; failed?: string[] }>,
  credentialSets?: Array<{ required?: boolean; options: string[][] }>
) {
  const isSatisfiable = (dcqlCredentialId: string) => (matches[dcqlCredentialId].valid ?? []).length > 0

  return {
    credentials: Object.keys(matches).map((id) => ({ id, format: 'dc+sd-jwt' })),
    credential_matches: Object.fromEntries(
      Object.entries(matches).map(([id, { valid = [], failed = [] }]) => [
        id,
        {
          success: valid.length > 0,
          credential_query_id: id,
          valid_credentials: valid.length > 0 ? valid.map(validCredential) : undefined,
          failed_credentials: failed.map((recordId) => ({
            record: record(recordId),
            meta: { success: false, issues: { vct: ['Expected vct to match'] } },
            claims: { success: true },
            trusted_authorities: { success: true },
          })),
        },
      ])
    ),
    credential_sets: credentialSets?.map(({ required = true, options }) => {
      const matchingOptions = options.filter((option) => option.every(isSatisfiable))
      return { required, options, matching_options: matchingOptions.length > 0 ? matchingOptions : undefined }
    }),
    can_be_satisfied: true,
  } as unknown as DcqlQueryResult
}

const select = (
  result: DcqlQueryResult,
  credentials: Array<{ dcqlCredentialId: string; credentialRecordId: string }>
) => {
  const selected = dcqlService.selectCredentialsForRequestById(result, { credentials })

  for (const [credential] of Object.values(selected)) {
    expect(credential.claimFormat).toBe(ClaimFormat.SdJwtDc)
    expect(credential.disclosedPayload).toEqual({ name: credential.credentialRecord.id })
  }

  return Object.fromEntries(
    Object.entries(selected).map(([dcqlCredentialId, [credential]]) => [
      dcqlCredentialId,
      credential.credentialRecord.id,
    ])
  )
}

describe('DcqlService.selectCredentialsForRequestById', () => {
  describe('single credential', () => {
    const result = queryResult({ patient: { valid: ['P1', 'P2'] } })

    test('presents the selected record', () => {
      expect(select(result, [{ dcqlCredentialId: 'patient', credentialRecordId: 'P2' }])).toEqual({ patient: 'P2' })
    })

    test('auto-selects when no record is selected', () => {
      expect(select(result, [])).toEqual({ patient: 'P1' })
    })
  })

  describe('multiple credentials, all required', () => {
    const result = queryResult({ patient: { valid: ['P1', 'P2'] }, pid: { valid: ['M1', 'M2'] } })

    test('presents the selected record for each DCQL credential id', () => {
      expect(
        select(result, [
          { dcqlCredentialId: 'patient', credentialRecordId: 'P2' },
          { dcqlCredentialId: 'pid', credentialRecordId: 'M2' },
        ])
      ).toEqual({ patient: 'P2', pid: 'M2' })
    })

    test('auto-selects the DCQL credential ids without a selected record', () => {
      expect(select(result, [{ dcqlCredentialId: 'pid', credentialRecordId: 'M2' }])).toEqual({
        patient: 'P1',
        pid: 'M2',
      })
    })

    test('behaves the same when written as a required credential set', () => {
      const withSet = queryResult({ patient: { valid: ['P1', 'P2'] }, pid: { valid: ['M1', 'M2'] } }, [
        { options: [['patient', 'pid']] },
      ])

      expect(
        select(withSet, [
          { dcqlCredentialId: 'patient', credentialRecordId: 'P2' },
          { dcqlCredentialId: 'pid', credentialRecordId: 'M2' },
        ])
      ).toEqual({ patient: 'P2', pid: 'M2' })
      expect(select(withSet, [{ dcqlCredentialId: 'pid', credentialRecordId: 'M2' }])).toEqual({
        patient: 'P1',
        pid: 'M2',
      })
    })
  })

  describe('records that are valid for several DCQL credential ids', () => {
    const result = queryResult({ a: { valid: ['1', '2'] }, b: { valid: ['1', '2'] } })

    test('presents each record for the DCQL credential id it is selected for', () => {
      expect(
        select(result, [
          { dcqlCredentialId: 'a', credentialRecordId: '1' },
          { dcqlCredentialId: 'b', credentialRecordId: '2' },
        ])
      ).toEqual({ a: '1', b: '2' })

      expect(
        select(result, [
          { dcqlCredentialId: 'a', credentialRecordId: '2' },
          { dcqlCredentialId: 'b', credentialRecordId: '1' },
        ])
      ).toEqual({ a: '2', b: '1' })
    })

    test('presents the same record for both when selected for both', () => {
      expect(
        select(result, [
          { dcqlCredentialId: 'a', credentialRecordId: '2' },
          { dcqlCredentialId: 'b', credentialRecordId: '2' },
        ])
      ).toEqual({ a: '2', b: '2' })
    })
  })

  describe('alternative options', () => {
    const result = queryResult({ patient: { valid: ['P1', 'P2'] }, pid: { valid: ['M1', 'M2'] } }, [
      { options: [['patient'], ['pid']] },
    ])

    test('presents the option the selected record is for', () => {
      expect(select(result, [{ dcqlCredentialId: 'pid', credentialRecordId: 'M2' }])).toEqual({ pid: 'M2' })
      expect(select(result, [{ dcqlCredentialId: 'patient', credentialRecordId: 'P2' }])).toEqual({ patient: 'P2' })
    })

    test('auto-selects the first option when no record is selected', () => {
      expect(select(result, [])).toEqual({ patient: 'P1' })
    })

    test('throws when records are selected for more than one option', () => {
      expect(() =>
        select(result, [
          { dcqlCredentialId: 'patient', credentialRecordId: 'P1' },
          { dcqlCredentialId: 'pid', credentialRecordId: 'M1' },
        ])
      ).toThrow(/DCQL credential id 'pid'.*is not presented/s)
    })

    test('presents the option with several credentials the selected records are for', () => {
      const withLargerOption = queryResult(
        { passport: { valid: ['X1'] }, patient: { valid: ['P1', 'P2'] }, pid: { valid: ['M1', 'M2'] } },
        [{ options: [['passport'], ['patient', 'pid']] }]
      )

      expect(select(withLargerOption, [{ dcqlCredentialId: 'pid', credentialRecordId: 'M2' }])).toEqual({
        patient: 'P1',
        pid: 'M2',
      })
    })

    test('throws when the selected record is not valid, instead of presenting another option', () => {
      const withFailed = queryResult({ patient: { valid: ['P1'] }, pid: { valid: ['M1'], failed: ['M2'] } }, [
        { options: [['patient'], ['pid']] },
      ])

      expect(() => select(withFailed, [{ dcqlCredentialId: 'pid', credentialRecordId: 'M2' }])).toThrow(
        /Credential record with id 'M2' exists but does not match the requirements for DCQL credential id 'pid'/
      )
    })
  })

  describe('optional credential sets', () => {
    const result = queryResult({ patient: { valid: ['P1', 'P2'] }, pid: { valid: ['M1', 'M2'] } }, [
      { options: [['patient']] },
      { required: false, options: [['pid']] },
    ])

    test('presents the selected record for the required set, and not the optional set', () => {
      expect(select(result, [{ dcqlCredentialId: 'patient', credentialRecordId: 'P2' }])).toEqual({ patient: 'P2' })
      expect(select(result, [])).toEqual({ patient: 'P1' })
    })

    test('throws when a record is selected for an optional set', () => {
      expect(() =>
        select(result, [
          { dcqlCredentialId: 'patient', credentialRecordId: 'P2' },
          { dcqlCredentialId: 'pid', credentialRecordId: 'M1' },
        ])
      ).toThrow(/DCQL credential id 'pid'.*is not presented/s)
    })
  })

  describe('invalid selections', () => {
    const result = queryResult({ patient: { valid: ['P1'], failed: ['P2'] }, pid: { valid: ['M1'] } })

    test('throws when the DCQL credential id is not in the query', () => {
      expect(() => select(result, [{ dcqlCredentialId: 'passport', credentialRecordId: 'P1' }])).toThrow(
        new DcqlError(
          "DCQL credential id 'passport' is not present in the dcql query. Available DCQL credential ids: patient, pid"
        )
      )
    })

    test('throws when a DCQL credential id is selected more than once', () => {
      expect(() =>
        select(result, [
          { dcqlCredentialId: 'pid', credentialRecordId: 'M1' },
          { dcqlCredentialId: 'pid', credentialRecordId: 'M1' },
        ])
      ).toThrow(new DcqlError("More than one credential record selected for DCQL credential id 'pid'"))
    })

    test('throws when the record does not match the DCQL credential id', () => {
      expect(() => select(result, [{ dcqlCredentialId: 'patient', credentialRecordId: 'P2' }])).toThrow(
        /Credential record with id 'P2' exists but does not match the requirements for DCQL credential id 'patient'.*Available valid credential record ids: P1/s
      )
    })

    test('throws when the record is unknown', () => {
      expect(() => select(result, [{ dcqlCredentialId: 'pid', credentialRecordId: 'P1' }])).toThrow(
        /Unable to find credential record with id 'P1' for DCQL credential id 'pid'. Available credential record ids: M1/
      )
    })

    test('throws when the request cannot be satisfied', () => {
      expect(() => select({ ...result, can_be_satisfied: false } as DcqlQueryResult, [])).toThrow(
        'Cannot select the credentials for the dcql query presentation if the request cannot be satisfied'
      )
    })
  })
})
