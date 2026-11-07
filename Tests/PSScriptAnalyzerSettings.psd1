@{
    Severity = @('Error', 'Warning', 'Information')
    # Each excluded rule is advice about style, or reports a false positive in this project:
    # the console tools print with Write-Host on purpose, WPF handlers bind unused sender
    # parameters, and several names are plural because they return collections.
    ExcludeRules = @(
        'PSAvoidUsingWriteHost'
        'PSReviewUnusedParameter'
        'PSUseSingularNouns'
        'PSAvoidUsingPositionalParameters'
        'PSAvoidTrailingWhitespace'
    )
}
