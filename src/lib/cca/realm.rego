package policy

realm contains ect if {
  # note: with the updated CCA profile, we no longer have a good way
  # of separting realm from platform elements as both environments
  # now solely use class-id. However, since we're accessing all
  # values by their mkey, this shouldn't matter; so we simply treat
  # the entire input as realm.
  ect = input[_]
}

refvals contains ect if {
  ect = realm[_]
  ect["cm-type"] == "reference-values"
}

evidence contains ect if {
  ect = realm[_]
  ect["cm-type"] == "evidence"
}

# If cryptographic verification completes (implicit in getting here), instance
# identity has been recognized.
instance_identity := RECOGNIZED_INSTANCE

rim_matched if {
  ref := refvals[_]["element-list"][_]
  ref.mkey == "cca.rim"
  ev := evidence[_]["element-list"][_]
  ev.mkey == "cca.rim"

  ref == ev
}

pv_matched if {
  ref := refvals[_]["element-list"][_]
  ref.mkey == "cca.rpv"
  ev := evidence[_]["element-list"][_]
  ev.mkey == "cca.rpv"

  ref == ev
}

ref_rems contains rem if {
  rv := refvals[_]["element-list"][_]
  rem := {
    "name": rv.mkey,
    "value": rv.mval,
  }
  rv.mkey != "cca.rim"
}

ev_rems contains rem if {
  rv := evidence[_]["element-list"][_]
  rem := {
    "name": rv.mkey,
    "value": rv.mval,
  }
  startswith(rv.mkey, "cca.rem")
}

rems_matched if {
  every ev in ev_rems {
    ref = ref_rems[_]
    ref == ev
  }
}

executables := APPROVED_RT if {
  rim_matched
  pv_matched
  rems_matched
} else := APPROVED_BOOT if {
  rim_matched
  pv_matched
} else := UNRECOGNIZED_RT

# TODO: this needs to be taken from runtime_opaque from the platfrom appraisal
runtime_opaque := ENCRYPTED_RT
