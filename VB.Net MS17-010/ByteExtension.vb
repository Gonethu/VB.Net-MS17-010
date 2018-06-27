Imports System.Runtime.CompilerServices

Module ByteExtension

    <Extension()>
    Public Function Add(ByRef src As Byte(), ByRef stringArr As Byte()) As Byte()
        Dim srcOriginalLength As Integer = src.Length
        Array.Resize(src, src.Length + stringArr.Length)
        Array.Copy(stringArr, 0, src, srcOriginalLength, stringArr.Length)
        Return src
    End Function

    <Extension()>
    Public Function Parse(ByRef src As Byte(), ByRef startIndex As Integer, ByRef length As Integer) As Byte()
        Dim newBytes() As Byte = New Byte(length - startIndex) {}

        Dim counter As Integer = 0
        For i As Integer = startIndex To length
            newBytes(counter) = src(i)
            counter += 1
        Next

        Return newBytes
    End Function

    <Extension()>
    Public Function Empty(ByRef src As Byte()) As Boolean
        For i As Integer = 0 To src.Length - 1
            If src(i) <> 0 Then
                Return False
            End If
        Next
        Return True
    End Function
End Module