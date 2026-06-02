package com.example.secureshield

import android.os.Bundle
import androidx.fragment.app.Fragment
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.lifecycle.lifecycleScope
import androidx.navigation.fragment.findNavController
import com.example.secureshield.databinding.FragmentFirstBinding
import com.secureshield.deepscan.DeepScanEngine
import com.secureshield.deepscan.DeepScanEngineImpl
import com.secureshield.deepscan.HardwareAttestationProviderImpl
import kotlinx.coroutines.launch

/**
 * A simple [Fragment] subclass as the default destination in the navigation.
 */
class FirstFragment : Fragment() {

    private var _binding: FragmentFirstBinding? = null

    // This property is only valid between onCreateView and
    // onDestroyView.
    private val binding get() = _binding!!

    private lateinit var deepScanEngine: DeepScanEngine

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {

        _binding = FragmentFirstBinding.inflate(inflater, container, false)
        return binding.root

    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        // Initialize security engine
        val attestationProvider = HardwareAttestationProviderImpl()
        deepScanEngine = DeepScanEngineImpl(attestationProvider)

        binding.buttonFirst.setOnClickListener {
            findNavController().navigate(R.id.action_FirstFragment_to_SecondFragment)
        }

        binding.buttonScan.setOnClickListener {
            runSecurityScan()
        }
    }

    private fun runSecurityScan() {
        binding.textviewStatus.text = "Status: Scanning..."
        binding.textviewResults.text = ""

        lifecycleScope.launch {
            val results = deepScanEngine.performFullDeviceScan()
            
            binding.textviewStatus.text = if (results.needsImmediateAction) {
                "Status: THREAT DETECTED"
            } else {
                "Status: Device Secure"
            }

            val resultText = StringBuilder()
            resultText.append("Hardware Integrity: ${if (results.hardwareIntegrityPassed) "PASSED" else "FAILED"}\n")
            if (results.fakeBankingApps.isNotEmpty()) {
                resultText.append("Fake Apps Detected: ${results.fakeBankingApps.joinToString(", ")}\n")
            } else {
                resultText.append("Fake Apps: None\n")
            }
            
            binding.textviewResults.text = resultText.toString()
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
