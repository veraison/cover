package policy

platform contains ect if {
  ect = input[_]
  ect.environment.class.id.type == "psa.impl-id"
}

refvals contains ect if {
  ect = platform[_]
  ect["cm-type"] == "reference-values"
}

evidence contains ect if {
  ect = platform[_]
  ect["cm-type"] == "evidence"
}

LC_ASSEMBLY_AND_TEST := 0
LC_CCA_ROT_PROVISIONING := 1
LC_SECURED := 2
LC_NON_CCA_PLATFORM_DEBUG := 3
LC_RECOVERABLE_CCA_PLATFORM_DEBUG := 4
LC_DECOMMISSIONED := 5

lifecycle := ret if {
  elt = evidence[_]["element-list"][_]
  elt.key.value == "lifecycle"

  ret := elt.value["raw-int"].value
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
  ref.key.type == "cca.platform-config-id"

  ev = evidence[_]["element-list"][_]
  ev.key.type == "cca.platform-config-id"

  ref.key.value == ev.key.value
  ref.value == ev.value
} else := UNSAFE_CONFIG

ev_sw contains ev if {
  ev := evidence[_]["element-list"][_]
  ev.key.type == "psa.refval-id"
}

executables := APPROVED_BOOT if {
  ev_sw[_]
  every ev in ev_sw {
    ref = refvals[_]["element-list"][_]
    ref.key.type == "psa.refval-id"

    ref.key.value == ev.key.value
    ref.value == ev.value
  }
} else := UNRECOGNIZED_RT

runtime_opaque := ENCRYPTED_RT if is_secured else = VISIBLE_RT

storage_opaque := HW_ENCRYPTED_SECRETS if is_secured else = UNENCRYPTED_SECRETS

# passed signature check (assumed to get here) and recognized SW indicate
# genuine HW
hardware := GENUINE_HW if {
  executables == APPROVED_BOOT
} else := UNRECOGNIZED_HW
