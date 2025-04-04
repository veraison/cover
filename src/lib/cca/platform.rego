package policy

CLAIM_RAW_INT := "-1"

TAG_PSA_IMPL_ID := 600
TAG_PSA_REFVAL_ID := 601
TAG_CCA_PLAT_CONFIG := 602

LC_UNKNOWN := 0
LC_ASSEMBLY_AND_TEST := 1
LC_CCA_ROT_PROVISIONING := 2
LC_SECURED := 3
LC_NON_CCA_PLATFORM_DEBUG := 4
LC_RECOVERABLE_CCA_PLATFORM_DEBUG := 5
LC_DECOMMISSIONED := 6

platform contains ect if {
  ect = input[_]
  ect.environment.class["class-id"].tag == TAG_PSA_IMPL_ID
}

refvals contains ect if {
  ect = platform[_]
  ect["cm-type"] == "reference-values"
}

evidence contains ect if {
  ect = platform[_]
  ect["cm-type"] == "evidence"
}

lifecycle := ret if {
  elt = evidence[_]["element-list"][_]
  elt.mkey == "lifecycle"

  ret := elt.mval[CLAIM_RAW_INT]
}

is_secured if { lifecycle == LC_SECURED }
is_secured if { lifecycle == LC_NON_CCA_PLATFORM_DEBUG }

# instance is recognized iff CPAK validation passed (implicit in getting to
# here), and there were refrence values identified associated with the
# instance.
instance_identity := RECOGNIZED_INSTANCE if {
  refvals[_]
  is_secured
} else := UNTRUSTWORTHY_INSTANCE if {
  refvals[_]
} else := UNRECOGNIZED_INSTANCE

configuration := APPROVED_CONFIG if {
  ref = refvals[_]["element-list"][_]
  ref.mkey.tag == TAG_CCA_PLAT_CONFIG

  ev = evidence[_]["element-list"][_]
  ev.mkey.tag == TAG_CCA_PLAT_CONFIG

  ref.mkey.value == ev.mkey.value
  ref.mval == ev.mval
} else := UNSAFE_CONFIG

ev_sw contains ev if {
  ev := evidence[_]["element-list"][_]
  ev.mkey.tag == TAG_PSA_REFVAL_ID
}

executables := APPROVED_BOOT if {
  ev_sw[_]
  every ev in ev_sw {
    ref = refvals[_]["element-list"][_]
    ref.mkey.tag == TAG_PSA_REFVAL_ID

    ref.mkey.value == ev.mkey.value
    ref.mval == ev.mval
  }
} else := UNRECOGNIZED_RT

runtime_opaque := ENCRYPTED_RT if is_secured else = VISIBLE_RT

storage_opaque := HW_ENCRYPTED_SECRETS if is_secured else = UNENCRYPTED_SECRETS

# passed signature check (assumed to get here) and recognized SW indicate
# genuine HW
hardware := GENUINE_HW if {
  executables == APPROVED_BOOT
} else := UNRECOGNIZED_HW
