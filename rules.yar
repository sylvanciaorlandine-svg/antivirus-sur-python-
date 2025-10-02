rule Block_Specific_Software {
    meta:
        description = "Bloque un logiciel malveillant spécifique"
        author = "TonNom"
    condition:
        hash.sha256(0, filesize) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}
